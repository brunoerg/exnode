defmodule Exnode.P2P.AddrMan.Table do
  @moduledoc """
  The address tables, a port of Core v32.1 `addrman.cpp` (`AddrManImpl`,
  `AddrInfo`). A pure value; `Exnode.P2P.AddrMan` holds one in a process.

  * **new** table: 1024 buckets × 64 positions. An address's bucket is a
    keyed hash of its group and its *source's* group, so one source group
    reaches at most 64 buckets (`GetNewBucket`). An address may sit in up
    to 8 new buckets (learned from several sources); each further reference
    is 2^n times harder to add.
  * **tried** table: 256 buckets × 64, keyed by the address and its group,
    8 buckets per group (`GetTriedBucket`). An address moves here after a
    successful outbound connection (`good/4`); the entry it displaces goes
    back to the new table.
  * **test-before-evict**: if moving to tried would displace an entry, the
    move is recorded as a collision (at most 10) and resolved later
    (`resolve_collisions/2`): the old entry stays if it was reachable in the
    last 4 hours, else it is replaced.
  * Bucket hashes are Core's (double SHA-256 over Core's serialization,
    first 8 bytes little-endian), with the secret 32-byte key, so Core's own
    bucket test vectors apply.
  * Selection (`select/4`): tried or new with equal odds, a random bucket
    and position, accepted with probability `GetChance` (lower after recent
    tries and each failure), raised 1.2× per rejection.

  Not ported: ASMap (Core's default is off), and Core's `vRandom` index
  (random sampling uses `Enum.shuffle`). Times are Unix seconds and passed
  in, so tests control the clock.

  Entry: `%{addr: %{net, addr, port}, services, time, source: %{net, addr},
  last_success, last_try, last_count_attempt, attempts, refs, in_tried}`,
  `refs` being the set of `{bucket, position}` it holds in the new table.
  """

  import Bitwise

  alias Exnode.Codec.CompactSize
  alias Exnode.P2P.NetAddr

  @tried_bucket_count 256
  @new_bucket_count 1024
  @bucket_size 64
  # addrman.h
  @tried_buckets_per_group 8
  @new_buckets_per_source_group 64
  @new_buckets_per_address 8
  @horizon 30 * 86_400
  @retries 3
  @max_failures 10
  @min_fail 7 * 86_400
  @replacement 4 * 3600
  @tried_collision_size 10
  @test_window 40 * 60
  # protocol.h CAddress::TIME_INIT
  @time_init 100_000_000

  defstruct key: nil,
            info: %{},
            ids: %{},
            new: %{},
            tried: %{},
            n_new: 0,
            n_tried: 0,
            next_id: 0,
            collisions: MapSet.new(),
            last_good: 1,
            net_counts: %{}

  def new(key \\ :crypto.strong_rand_bytes(32)) when byte_size(key) == 32,
    do: %__MODULE__{key: key}

  def time_init, do: @time_init

  @doc "Lookup key of a service: `{net, addr_bytes, port}`."
  def key(%{net: n, addr: a, port: p}), do: {n, a, p}

  def size(%__MODULE__{} = t), do: map_size(t.info)
  def size(%__MODULE__{} = t, :new), do: t.n_new
  def size(%__MODULE__{} = t, :tried), do: t.n_tried

  def get(%__MODULE__{} = t, key), do: (id = t.ids[key]) && t.info[id]

  # --- bucket placement (AddrInfo::Get*Bucket, GetBucketPosition) --------------

  defp cheap_hash(iodata) do
    <<n::little-64, _::binary>> = Exnode.Crypto.Hash.hash256(iodata)
    n
  end

  defp vec(bin), do: CompactSize.encode_bytes(bin)

  @doc "Core `AddrInfo::GetTriedBucket`."
  def tried_bucket(key, addr) do
    h1 = cheap_hash([key, vec(NetAddr.service_key(addr))])

    h2 =
      cheap_hash([
        key,
        vec(NetAddr.group(addr)),
        <<rem(h1, @tried_buckets_per_group)::little-64>>
      ])

    rem(h2, @tried_bucket_count)
  end

  @doc "Core `AddrInfo::GetNewBucket`."
  def new_bucket(key, addr, source) do
    src_group = NetAddr.group(source)
    h1 = cheap_hash([key, vec(NetAddr.group(addr)), vec(src_group)])
    h2 = cheap_hash([key, vec(src_group), <<rem(h1, @new_buckets_per_source_group)::little-64>>])
    rem(h2, @new_bucket_count)
  end

  @doc "Core `AddrInfo::GetBucketPosition`."
  def bucket_position(key, new?, bucket, addr) do
    h =
      cheap_hash([
        key,
        if(new?, do: "N", else: "K"),
        <<bucket::little-32>>,
        vec(NetAddr.service_key(addr))
      ])

    rem(h, @bucket_size)
  end

  # --- entry quality (AddrInfo::IsTerrible, GetChance) ------------------------

  @doc "Core `AddrInfo::IsTerrible`."
  def terrible?(i, now) do
    cond do
      now - i.last_try <= 60 -> false
      i.time > now + 600 -> true
      now - i.time > @horizon -> true
      i.last_success == 0 and i.attempts >= @retries -> true
      now - i.last_success > @min_fail and i.attempts >= @max_failures -> true
      true -> false
    end
  end

  @doc "Core `AddrInfo::GetChance`."
  def chance(i, now) do
    c = if now - i.last_try < 600, do: 0.01, else: 1.0
    c * :math.pow(0.66, min(i.attempts, 8))
  end

  # --- adding (AddSingle, Add_) ------------------------------------------------

  @doc """
  Core `Add_`: adds `addrs` (maps with `net, addr, port`, optional
  `services`, `time`) learned from `source` (an address, or
  `NetAddr.internal(name)`), with `penalty` seconds taken off their times.
  Returns `{table, number_added}`.
  """
  def add(%__MODULE__{} = t, addrs, source, penalty, now) do
    Enum.reduce(addrs, {t, 0}, fn a, {t, n} ->
      {t, added} = add_single(t, a, source, penalty, now)
      {t, if(added, do: n + 1, else: n)}
    end)
  end

  defp add_single(t, a, source, penalty, now) do
    addr = Map.take(a, [:net, :addr, :port])
    k = key(addr)

    if not NetAddr.routable?(addr) do
      {t, false}
    else
      # No penalty for a source announcing itself.
      penalty = if source.net == addr.net and source.addr == addr.addr, do: 0, else: penalty
      atime = Map.get(a, :time) || @time_init
      services = Map.get(a, :services, 0)

      case t.ids[k] do
        nil ->
          info = %{
            addr: addr,
            services: services,
            time: max(0, atime - penalty),
            source: Map.take(source, [:net, :addr]),
            last_success: 0,
            last_try: 0,
            last_count_attempt: 0,
            attempts: 0,
            refs: MapSet.new(),
            in_tried: false
          }

          id = t.next_id

          t = %{
            t
            | info: Map.put(t.info, id, info),
              ids: Map.put(t.ids, k, id),
              next_id: id + 1,
              n_new: t.n_new + 1
          }

          place_new(count(t, addr.net, :new, 1), id, source, now)

        id ->
          info = t.info[id]
          # Periodically update the time (hourly if currently online, else daily).
          interval = if now - atime < 86_400, do: 3600, else: 86_400

          info =
            if info.time < atime - interval - penalty,
              do: %{info | time: max(0, atime - penalty)},
              else: info

          info = %{info | services: bor(info.services, services)}
          t = put_in(t.info[id], info)
          refs = MapSet.size(info.refs)

          cond do
            atime <= info.time -> {t, false}
            info.in_tried -> {t, false}
            refs == @new_buckets_per_address -> {t, false}
            # Stochastic test: n existing references make it 2^n times harder.
            refs > 0 and :rand.uniform(1 <<< refs) != 1 -> {t, false}
            true -> place_new(t, id, source, now)
          end
      end
    end
  end

  defp place_new(t, id, source, now) do
    info = t.info[id]
    b = new_bucket(t.key, info.addr, source)
    p = bucket_position(t.key, true, b, info.addr)

    case t.new[{b, p}] do
      ^id ->
        {t, false}

      occupant ->
        # Overwrite a terrible entry, or one also held elsewhere when this one is held nowhere.
        insert =
          occupant == nil or
            (fn o ->
               terrible?(o, now) or (MapSet.size(o.refs) > 1 and MapSet.size(info.refs) == 0)
             end).(t.info[occupant])

        if insert do
          t = clear_new(t, b, p)
          t = %{t | new: Map.put(t.new, {b, p}, id)}
          {update_in(t.info[id].refs, &MapSet.put(&1, {b, p})), true}
        else
          t = if MapSet.size(t.info[id].refs) == 0, do: delete(t, id), else: t
          {t, false}
        end
    end
  end

  defp clear_new(t, b, p) do
    case t.new[{b, p}] do
      nil ->
        t

      id ->
        t = %{t | new: Map.delete(t.new, {b, p})}
        t = update_in(t.info[id].refs, &MapSet.delete(&1, {b, p}))

        if MapSet.size(t.info[id].refs) == 0 and not t.info[id].in_tried,
          do: delete(t, id),
          else: t
    end
  end

  defp delete(t, id) do
    info = t.info[id]

    t = %{
      t
      | info: Map.delete(t.info, id),
        ids: Map.delete(t.ids, key(info.addr)),
        n_new: t.n_new - 1,
        collisions: MapSet.delete(t.collisions, id)
    }

    count(t, info.addr.net, :new, -1)
  end

  defp count(t, net, which, d) do
    {n, tr} = Map.get(t.net_counts, net, {0, 0})
    v = if which == :new, do: {n + d, tr}, else: {n, tr + d}
    %{t | net_counts: Map.put(t.net_counts, net, v)}
  end

  # --- moving to tried (Good_, MakeTried) --------------------------------------

  @doc """
  Core `Good_`: a successful outbound connection to `key`. With
  `test_before_evict`, a move that would displace a tried entry is recorded
  as a collision instead. Returns `{table, moved_to_tried}`.
  """
  def good(%__MODULE__{} = t, key, test_before_evict \\ true, now) do
    t = %{t | last_good: now}

    case t.ids[key] do
      nil ->
        {t, false}

      id ->
        t = update_in(t.info[id], &%{&1 | last_success: now, last_try: now, attempts: 0})
        info = t.info[id]

        cond do
          info.in_tried ->
            {t, false}

          MapSet.size(info.refs) == 0 ->
            {t, false}

          true ->
            tb = tried_bucket(t.key, info.addr)
            tp = bucket_position(t.key, false, tb, info.addr)

            if test_before_evict and Map.has_key?(t.tried, {tb, tp}) do
              c =
                if MapSet.size(t.collisions) < @tried_collision_size,
                  do: MapSet.put(t.collisions, id),
                  else: t.collisions

              {%{t | collisions: c}, false}
            else
              {make_tried(t, id), true}
            end
        end
    end
  end

  defp make_tried(t, id) do
    info = t.info[id]
    new = Map.drop(t.new, MapSet.to_list(info.refs))
    t = %{t | new: new, n_new: t.n_new - 1} |> count(info.addr.net, :new, -1)
    t = put_in(t.info[id].refs, MapSet.new())

    tb = tried_bucket(t.key, info.addr)
    tp = bucket_position(t.key, false, tb, info.addr)

    t =
      case t.tried[{tb, tp}] do
        nil ->
          t

        old_id ->
          # The displaced entry goes back to the new table.
          old = t.info[old_id]

          t =
            %{t | tried: Map.delete(t.tried, {tb, tp}), n_tried: t.n_tried - 1}
            |> count(old.addr.net, :tried, -1)

          t = put_in(t.info[old_id].in_tried, false)
          nb = new_bucket(t.key, old.addr, old.source)
          np = bucket_position(t.key, true, nb, old.addr)
          t = clear_new(t, nb, np)
          t = put_in(t.info[old_id].refs, MapSet.new([{nb, np}]))

          %{t | new: Map.put(t.new, {nb, np}, old_id), n_new: t.n_new + 1}
          |> count(old.addr.net, :new, 1)
      end

    t =
      %{t | tried: Map.put(t.tried, {tb, tp}, id), n_tried: t.n_tried + 1}
      |> count(info.addr.net, :tried, 1)

    put_in(t.info[id].in_tried, true)
  end

  # --- attempts and connections ------------------------------------------------

  @doc "Core `Attempt_`: a connection attempt; a failure counts once per success epoch."
  def attempt(%__MODULE__{} = t, key, count_failure, now) do
    case t.ids[key] do
      nil ->
        t

      id ->
        update_in(t.info[id], fn i ->
          i = %{i | last_try: now}

          if count_failure and i.last_count_attempt < t.last_good,
            do: %{i | last_count_attempt: now, attempts: i.attempts + 1},
            else: i
        end)
    end
  end

  @doc "Core `Connected_`: the peer was connected; refresh its time (at most every 20 min)."
  def connected(%__MODULE__{} = t, key, now) do
    case t.ids[key] do
      nil ->
        t

      id ->
        update_in(t.info[id], fn i -> if now - i.time > 1200, do: %{i | time: now}, else: i end)
    end
  end

  @doc "Core `SetServices_`."
  def set_services(%__MODULE__{} = t, key, services) do
    case t.ids[key] do
      nil -> t
      id -> put_in(t.info[id].services, services)
    end
  end

  # --- selection (Select_, GetAddr_) -------------------------------------------

  @doc """
  Core `Select_`: an entry to connect to, or nil. `new_only` for feelers;
  `networks` limits the networks considered (nil = all).
  """
  def select(%__MODULE__{} = t, new_only, networks, now) do
    {new_count, tried_count} =
      case networks do
        nil ->
          {t.n_new, t.n_tried}

        nets ->
          Enum.reduce(nets, {0, 0}, fn n, {a, b} ->
            {x, y} = Map.get(t.net_counts, n, {0, 0})
            {a + x, b + y}
          end)
      end

    cond do
      map_size(t.info) == 0 ->
        nil

      new_only and new_count == 0 ->
        nil

      new_count + tried_count == 0 ->
        nil

      true ->
        search_tried =
          cond do
            new_only or tried_count == 0 -> false
            new_count == 0 -> true
            true -> :rand.uniform(2) == 1
          end

        select_loop(t, search_tried, networks, now, 1.0, 0)
    end
  end

  # A safety bound Core does not need (its counts keep the loop finite).
  defp select_loop(_t, _tried, _nets, _now, _cf, n) when n > 200_000, do: nil

  defp select_loop(t, search_tried, nets, now, chance_factor, n) do
    {table, buckets} =
      if search_tried, do: {t.tried, @tried_bucket_count}, else: {t.new, @new_bucket_count}

    bucket = :rand.uniform(buckets) - 1
    start = :rand.uniform(@bucket_size) - 1

    found =
      Enum.find_value(0..(@bucket_size - 1), fn i ->
        id = table[{bucket, rem(start + i, @bucket_size)}]
        if id != nil and (nets == nil or t.info[id].addr.net in nets), do: id
      end)

    case found do
      nil ->
        select_loop(t, search_tried, nets, now, chance_factor, n + 1)

      id ->
        info = t.info[id]

        if :rand.uniform(1 <<< 30) - 1 < chance_factor * chance(info, now) * (1 <<< 30),
          do: info,
          else: select_loop(t, search_tried, nets, now, chance_factor * 1.2, n + 1)
    end
  end

  @doc """
  Core `GetAddr_`: up to `max` (0 = no limit) and `pct` percent of the
  entries, in random order, without terrible ones when `filtered`.
  """
  def get_addr(%__MODULE__{} = t, max, pct, now, filtered \\ true) do
    n = map_size(t.info)
    n = if pct != 0, do: div(min(pct, 100) * n, 100), else: n
    n = if max != 0, do: min(n, max), else: n

    t.info
    |> Map.values()
    |> Enum.shuffle()
    |> Stream.reject(&(filtered and terrible?(&1, now)))
    |> Enum.take(n)
  end

  # --- collisions (ResolveCollisions_, SelectTriedCollision_) ------------------

  @doc "Core `SelectTriedCollision_`: the tried entry a pending move would displace (to test with a feeler), or nil."
  def select_tried_collision(%__MODULE__{} = t) do
    case Enum.to_list(t.collisions) do
      [] ->
        {t, nil}

      ids ->
        id = Enum.random(ids)

        case t.info[id] do
          nil ->
            {%{t | collisions: MapSet.delete(t.collisions, id)}, nil}

          info ->
            tb = tried_bucket(t.key, info.addr)
            tp = bucket_position(t.key, false, tb, info.addr)
            {t, (old = t.tried[{tb, tp}]) && t.info[old]}
        end
    end
  end

  @doc """
  Core `ResolveCollisions_`: for each pending move, keep the old tried
  entry if it connected in the last 4 hours; replace it if a recent attempt
  to it failed (after giving it 60 s), or if the collision is older than 40
  minutes.
  """
  def resolve_collisions(%__MODULE__{} = t, now) do
    Enum.reduce(Enum.sort(t.collisions), t, fn id, t ->
      case t.info[id] do
        nil ->
          erase_collision(t, id)

        info_new ->
          tb = tried_bucket(t.key, info_new.addr)
          tp = bucket_position(t.key, false, tb, info_new.addr)

          case t.tried[{tb, tp}] do
            nil ->
              erase_collision(t, id)

            old_id ->
              old = t.info[old_id]

              cond do
                not NetAddr.valid?(info_new.addr) ->
                  erase_collision(t, id)

                now - old.last_success < @replacement ->
                  erase_collision(t, id)

                now - old.last_try < @replacement ->
                  if now - old.last_try > 60 do
                    {t, _} = good(t, key(info_new.addr), false, now)
                    erase_collision(t, id)
                  else
                    t
                  end

                now - info_new.last_success > @test_window ->
                  {t, _} = good(t, key(info_new.addr), false, now)
                  erase_collision(t, id)

                true ->
                  t
              end
          end
      end
    end)
  end

  defp erase_collision(t, id), do: %{t | collisions: MapSet.delete(t.collisions, id)}

  @doc "Core `FindAddressEntry_`: `%{tried, multiplicity, bucket, position}` or nil."
  def find_entry(%__MODULE__{} = t, key) do
    case get(t, key) do
      nil ->
        nil

      %{in_tried: true} = i ->
        b = tried_bucket(t.key, i.addr)

        %{
          tried: true,
          multiplicity: 1,
          bucket: b,
          position: bucket_position(t.key, false, b, i.addr)
        }

      i ->
        b = new_bucket(t.key, i.addr, i.source)

        %{
          tried: false,
          multiplicity: MapSet.size(i.refs),
          bucket: b,
          position: bucket_position(t.key, true, b, i.addr)
        }
    end
  end

  # --- persistence (the contents of Core's Serialize / Unserialize) ------------

  @doc "The table as a plain term: the key, and each entry with its new buckets."
  def to_term(%__MODULE__{} = t) do
    entries =
      for {_id, i} <- t.info do
        %{i | refs: Enum.map(i.refs, &elem(&1, 0))}
      end

    %{key: t.key, entries: entries}
  end

  @doc """
  Rebuilds a table from `to_term/1`, as Core's `Unserialize`: tried
  entries go back to their tried slot (lost if it is taken or the address is
  invalid), new entries to their saved buckets (at most 8, positions
  recomputed), and new entries left without a bucket are dropped.
  """
  def from_term(%{key: key, entries: entries}) when byte_size(key) == 32 do
    t = new(key)

    {tried, new} = Enum.split_with(entries, & &1.in_tried)

    t =
      Enum.reduce(tried, t, fn e, t ->
        tb = tried_bucket(key, e.addr)
        tp = bucket_position(key, false, tb, e.addr)

        if NetAddr.valid?(e.addr) and not Map.has_key?(t.tried, {tb, tp}) and
             not Map.has_key?(t.ids, key(e.addr)) do
          id = t.next_id
          info = %{e | refs: MapSet.new(), in_tried: true}

          t = %{
            t
            | info: Map.put(t.info, id, info),
              ids: Map.put(t.ids, key(e.addr), id),
              next_id: id + 1,
              tried: Map.put(t.tried, {tb, tp}, id),
              n_tried: t.n_tried + 1
          }

          count(t, e.addr.net, :tried, 1)
        else
          t
        end
      end)

    Enum.reduce(new, t, fn e, t ->
      if NetAddr.valid?(e.addr) and not Map.has_key?(t.ids, key(e.addr)) do
        refs =
          e.refs
          |> Enum.uniq()
          |> Enum.filter(&(&1 in 0..(@new_bucket_count - 1)))
          |> Enum.take(@new_buckets_per_address)
          |> Enum.map(&{&1, bucket_position(key, true, &1, e.addr)})
          |> Enum.reject(&Map.has_key?(t.new, &1))

        if refs == [] do
          t
        else
          id = t.next_id
          info = %{e | refs: MapSet.new(refs), in_tried: false}
          new = Enum.reduce(refs, t.new, &Map.put(&2, &1, id))

          t = %{
            t
            | info: Map.put(t.info, id, info),
              ids: Map.put(t.ids, key(e.addr), id),
              next_id: id + 1,
              new: new,
              n_new: t.n_new + 1
          }

          count(t, e.addr.net, :new, 1)
        end
      else
        t
      end
    end)
  end
end
