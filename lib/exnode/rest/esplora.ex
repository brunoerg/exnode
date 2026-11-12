defmodule Exnode.REST.Esplora do
  @moduledoc """
  Esplora-style REST API (Blockstream Esplora / electrs HTTP API), the
  subset wallets use, built on the archive, the
  scripthash index and the mempool; no separate indexer.

  Blocks: `GET /blocks/tip/height`, `/blocks/tip/hash`, `/block-height/:h`,
  `/block/:hash`, `/block/:hash/status`, `/block/:hash/txids`,
  `/block/:hash/raw`, `/block/:hash/header`.
  Transactions: `GET /tx/:txid`, `/tx/:txid/hex`, `/tx/:txid/raw`,
  `/tx/:txid/status`, `/tx/:txid/outspends`, `/tx/:txid/merkle-proof`;
  `POST /tx` (hex body).
  Addresses: `GET /address/:addr` (and `/scripthash/:sha256-hex`), `.../txs`,
  `.../txs/chain/:last_seen_txid`, `.../utxo`.
  Mempool: `GET /mempool`. `GET /fee-estimates` returns `{}` (exnode has no
  fee estimator, by design).

  Scripts are described as electrs does: rust-bitcoin `asm` and its script
  type names.

  Cost (the API is unauthenticated): a tx is read alone from the archive
  (`Archive.read_tx/2`), never by rebuilding its block; prevouts are point
  reads, batched per response (`Archive.outputs/2`), with the mempool looked
  up once per tx (or once per `/txs` page). No request copies the mempool:
  each asks it for what it needs (`Mempool.script_txs/2` from the mempool's
  script index for the address endpoints, `Mempool.spenders/2` for
  outspends, `Mempool.fee_rates/1` for `/mempool`). Confirmed spenders come
  from the archive's spend records (`Archive.spenders/2`: one seek per
  output, one tx read per spender; no address history, and no scripthash
  index needed). An address's confirmed
  stats are the index's per-script totals (`Scripthash.totals/2`), not a
  history scan; `/utxo` still scans the history, in the request's process,
  and `/txs` pages read only their rows (a reverse seek from the last seen
  tx).
  """
  use Plug.Router, copy_opts_to_assign: :opts

  alias Exnode.{Address, Archive, Mempool}
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Index.Scripthash
  alias Exnode.Mempool.Policy

  # Each connection process is an archive reader the fd budget counts (IDX-2).
  plug(:limit_reads)
  plug(:match)
  plug(:dispatch)

  defp limit_reads(conn, _opts) do
    Exnode.Archive.Segments.limit_read_handles(Exnode.FdBudget.api_read_handles())
    conn
  end

  def child_spec(opts) do
    Supervisor.child_spec(
      {Bandit,
       plug: {__MODULE__, %{ctx: Keyword.fetch!(opts, :ctx)}},
       port: Keyword.fetch!(opts, :port),
       ip: Keyword.get(opts, :ip, {127, 0, 0, 1}),
       startup_log: false,
       thousand_island_options: Exnode.FdBudget.api_server_options()},
      id: Keyword.get(opts, :id, __MODULE__)
    )
  end

  # --- blocks ---------------------------------------------------------------------

  get("/blocks/tip/height", do: text(conn, Integer.to_string(tip(conn.assigns.opts).height)))
  get("/blocks/tip/hash", do: text(conn, Hash.to_hex(tip(conn.assigns.opts).hash)))

  get "/block-height/:h" do
    t = tip_entry(conn.assigns.opts)

    case Integer.parse(h) do
      {n, ""} when n >= 0 and n <= t.height ->
        text(conn, Hash.to_hex(HeaderIndex.ancestor(idx(conn.assigns.opts), t, n).hash))

      _ ->
        err(conn, 404, "Block not found")
    end
  end

  get "/block/:hash" do
    with_block(conn, conn.assigns.opts, hash, fn e, b ->
      json(conn, block_json(conn.assigns.opts, e, b))
    end)
  end

  get "/block/:hash/status" do
    with_header(conn, conn.assigns.opts, hash, fn e ->
      json(conn, block_status(conn.assigns.opts, e))
    end)
  end

  get "/block/:hash/txids" do
    with_block(conn, conn.assigns.opts, hash, fn _e, b ->
      json(conn, Enum.map(b.txs, &Hash.to_hex(&1.txid)))
    end)
  end

  get "/block/:hash/raw" do
    with_block(conn, conn.assigns.opts, hash, fn _e, b ->
      conn |> put_resp_content_type("application/octet-stream") |> send_resp(200, b.raw)
    end)
  end

  get "/block/:hash/header" do
    with_header(conn, conn.assigns.opts, hash, fn e ->
      text(conn, Base.encode16(e.raw, case: :lower))
    end)
  end

  # --- transactions -----------------------------------------------------------------

  get "/tx/:txid" do
    with_tx(conn, conn.assigns.opts, txid, fn found ->
      json(conn, tx_json(conn.assigns.opts, found))
    end)
  end

  get "/tx/:txid/hex" do
    with_tx(conn, conn.assigns.opts, txid, fn found ->
      text(conn, Base.encode16(tx_of(found).raw, case: :lower))
    end)
  end

  get "/tx/:txid/raw" do
    with_tx(conn, conn.assigns.opts, txid, fn found ->
      conn
      |> put_resp_content_type("application/octet-stream")
      |> send_resp(200, tx_of(found).raw)
    end)
  end

  get "/tx/:txid/status" do
    with_tx(conn, conn.assigns.opts, txid, fn found ->
      json(conn, tx_status(conn.assigns.opts, found))
    end)
  end

  get "/tx/:txid/outspends" do
    with_tx(conn, conn.assigns.opts, txid, fn found ->
      json(conn, outspends(conn.assigns.opts, tx_of(found)))
    end)
  end

  get "/tx/:txid/merkle-proof" do
    with_tx(conn, conn.assigns.opts, txid, fn
      {:block, _tx, _header, e, pos} ->
        a = reader(conn.assigns.opts)
        {:ok, b} = Archive.read_block_txs(a, Archive.block_id(a, e.hash))
        json(conn, %{block_height: e.height, merkle: merkle_branch(b, pos), pos: pos})

      _ ->
        err(conn, 400, "Transaction not confirmed")
    end)
  end

  post "/tx" do
    {:ok, body, conn} = Plug.Conn.read_body(conn)

    with {:ok, raw} <- Base.decode16(String.trim(body), case: :mixed),
         {:ok, tx} <- Tx.decode_exact(raw) do
      case Mempool.accept(conn.assigns.opts.ctx.mempool, tx, unbroadcast: true) do
        {:ok, _} ->
          text(conn, Hash.to_hex(tx.txid))

        {:error, e} ->
          err(
            conn,
            400,
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"#{e.reason}\"}"
          )
      end
    else
      _ -> err(conn, 400, "Invalid transaction hex")
    end
  end

  # --- addresses / scripthashes ----------------------------------------------------

  get("/address/:addr",
    do:
      with_script(conn, conn.assigns.opts, {:address, addr}, fn sh, label ->
        json(conn, stats(conn.assigns.opts, sh, label))
      end)
  )

  get("/scripthash/:sh",
    do:
      with_script(conn, conn.assigns.opts, {:scripthash, sh}, fn h, label ->
        json(conn, stats(conn.assigns.opts, h, label))
      end)
  )

  get("/address/:addr/txs",
    do:
      with_script(conn, conn.assigns.opts, {:address, addr}, fn sh, _ ->
        json(conn, txs_page(conn.assigns.opts, sh, nil, true))
      end)
  )

  get("/scripthash/:sh/txs",
    do:
      with_script(conn, conn.assigns.opts, {:scripthash, sh}, fn h, _ ->
        json(conn, txs_page(conn.assigns.opts, h, nil, true))
      end)
  )

  get "/address/:addr/txs/chain/:last" do
    with_script(conn, conn.assigns.opts, {:address, addr}, fn sh, _ ->
      json(conn, txs_page(conn.assigns.opts, sh, last, false))
    end)
  end

  get "/scripthash/:sh/txs/chain/:last" do
    with_script(conn, conn.assigns.opts, {:scripthash, sh}, fn h, _ ->
      json(conn, txs_page(conn.assigns.opts, h, last, false))
    end)
  end

  get("/address/:addr/utxo",
    do:
      with_script(conn, conn.assigns.opts, {:address, addr}, fn sh, _ ->
        json(conn, utxos(conn.assigns.opts, sh))
      end)
  )

  get("/scripthash/:sh/utxo",
    do:
      with_script(conn, conn.assigns.opts, {:scripthash, sh}, fn h, _ ->
        json(conn, utxos(conn.assigns.opts, h))
      end)
  )

  # --- mempool / fees ----------------------------------------------------------------

  get "/mempool" do
    {pairs, total_vsize} = Mempool.fee_rates(conn.assigns.opts.ctx.mempool)

    hist =
      pairs
      |> Enum.map(fn {fee, vsize} -> {fee / vsize, vsize} end)
      |> Enum.sort(:desc)
      |> Enum.chunk_by(fn {r, _} -> round(r * 10) end)
      |> Enum.map(fn group ->
        [elem(hd(group), 0), Enum.reduce(group, 0, &(&2 + elem(&1, 1)))]
      end)

    json(conn, %{
      count: length(pairs),
      vsize: total_vsize,
      total_fee: Enum.reduce(pairs, 0, &(&2 + elem(&1, 0))),
      fee_histogram: hist
    })
  end

  get("/fee-estimates", do: json(conn, %{}))

  match(_, do: err(conn, 404, "Not Found"))

  # --- helpers ----------------------------------------------------------------------

  defp ctx(opts), do: opts.ctx
  defp idx(opts), do: Headers.index(ctx(opts).headers)
  # The committed tip, from the lock-free reader: block data up to it is readable.
  defp tip(opts), do: Archive.tip(reader(opts))
  defp reader(opts), do: ChainState.reader(ctx(opts).chain_state)
  defp tip_entry(opts), do: HeaderIndex.lookup(idx(opts), tip(opts).hash)
  defp network(opts), do: ctx(opts).params.network

  defp text(conn, s), do: conn |> put_resp_content_type("text/plain") |> send_resp(200, s)

  defp json(conn, data),
    do: conn |> put_resp_content_type("application/json") |> send_resp(200, Jason.encode!(data))

  defp err(conn, status, msg),
    do: conn |> put_resp_content_type("text/plain") |> send_resp(status, msg)

  defp parse_hash(h) do
    case byte_size(h) == 64 && Base.decode16(h, case: :mixed) do
      {:ok, _} -> {:ok, Hash.from_hex(String.downcase(h))}
      _ -> :error
    end
  end

  defp with_header(conn, opts, h, f) do
    with {:ok, hash} <- parse_hash(h),
         %{} = e <- HeaderIndex.lookup(idx(opts), hash) do
      f.(e)
    else
      _ -> err(conn, 404, "Block not found")
    end
  end

  defp with_block(conn, opts, h, f) do
    with_header(conn, opts, h, fn e ->
      a = reader(opts)

      case (id = Archive.block_id(a, e.hash)) && Archive.read_block_txs(a, id) do
        {:ok, b} -> f.(e, b)
        _ -> err(conn, 404, "Block not found")
      end
    end)
  end

  defp active?(opts, e) do
    t = tip_entry(opts)
    e.height <= t.height and HeaderIndex.ancestor(idx(opts), t, e.height).hash == e.hash
  end

  defp block_status(opts, e) do
    t = tip_entry(opts)

    if active?(opts, e) do
      next =
        if e.height < t.height,
          do: Hash.to_hex(HeaderIndex.ancestor(idx(opts), t, e.height + 1).hash)

      %{in_best_chain: true, height: e.height, next_best: next}
    else
      %{in_best_chain: false}
    end
  end

  defp block_json(opts, e, b) do
    stripped = IO.iodata_length(Block.encode(b, witness: false))
    h = b.header

    %{
      id: Hash.to_hex(e.hash),
      height: e.height,
      version: h.version,
      timestamp: h.time,
      tx_count: length(b.txs),
      size: byte_size(b.raw),
      weight: stripped * 3 + byte_size(b.raw),
      merkle_root: Hash.to_hex(h.merkle_root),
      previousblockhash: if(e.height > 0, do: Hash.to_hex(h.prev_hash)),
      mediantime: HeaderIndex.median_time_past(idx(opts), e),
      nonce: h.nonce,
      bits: h.bits,
      difficulty: Exnode.RPC.Methods.difficulty(h.bits)
    }
  end

  # A tx: {:mempool, tx} or {:block, tx, header, header_entry, pos}.
  defp with_tx(conn, opts, t, f) do
    with {:ok, txid} <- parse_hash(t),
         found when found != nil <- find_tx(opts, txid) do
      f.(found)
    else
      _ -> err(conn, 404, "Transaction not found")
    end
  end

  # `known`: the mempool txs the caller already fetched, `%{txid => tx}`
  # (else one mempool call).
  defp find_tx(opts, txid, known \\ nil) do
    case mempool_txs(opts, [txid], known) do
      %{^txid => tx} ->
        {:mempool, tx}

      _ ->
        case Archive.read_tx(reader(opts), txid) do
          :missing ->
            nil

          {:ok, tx, header, _id, pos} ->
            {:block, tx, header, HeaderIndex.lookup(idx(opts), header.hash), pos}
        end
    end
  end

  # The mempool txs among `txids`: `%{txid => tx}`, from `known` or one call.
  defp mempool_txs(_opts, [], _known), do: %{}

  defp mempool_txs(opts, txids, nil) do
    {found, _} = Mempool.get_txs(ctx(opts).mempool, for(t <- txids, do: %{type: :tx, hash: t}))
    Map.new(found, &{&1.txid, &1})
  end

  defp mempool_txs(_opts, txids, known),
    do: for(t <- txids, tx = known[t], into: %{}, do: {t, tx})

  defp tx_of({:mempool, tx}), do: tx
  defp tx_of({:block, tx, _, _, _}), do: tx

  defp tx_status(_opts, {:mempool, _}), do: %{confirmed: false}

  defp tx_status(opts, {:block, _, header, e, _}) do
    if active?(opts, e),
      do: %{
        confirmed: true,
        block_height: e.height,
        block_hash: Hash.to_hex(e.hash),
        block_time: header.time
      },
      else: %{confirmed: false}
  end

  # The outputs `outpoints` spend: `%{op => %Tx.Out{} | nil}`, mempool first
  # (`known` or one call), then one batched archive read (the newest
  # occurrence on the active chain).
  defp prevouts(opts, outpoints, known) do
    mem = mempool_txs(opts, outpoints |> Enum.map(&elem(&1, 0)) |> Enum.uniq(), known)

    chain =
      Archive.outputs(reader(opts), Enum.reject(outpoints, fn {t, _} -> Map.has_key?(mem, t) end))

    Map.new(outpoints, fn {t, v} = op ->
      {op, if(tx = mem[t], do: Enum.at(tx.outputs, v), else: chain[op])}
    end)
  end

  defp tx_json(opts, found, known \\ nil) do
    tx = tx_of(found)
    coinbase = Tx.coinbase?(tx)
    ops = for i <- tx.inputs, do: {i.prev_hash, i.prev_index}

    prevouts =
      if coinbase, do: [], else: (fn m -> Enum.map(ops, &m[&1]) end).(prevouts(opts, ops, known))

    vin =
      tx.inputs
      |> Enum.with_index()
      |> Enum.map(fn {i, n} ->
        po = if coinbase, do: nil, else: Enum.at(prevouts, n)

        base = %{
          txid: Hash.to_hex(i.prev_hash),
          vout: i.prev_index,
          prevout: po && out_json(opts, po),
          scriptsig: hex(i.script_sig),
          scriptsig_asm: asm(i.script_sig),
          is_coinbase: coinbase,
          sequence: i.sequence
        }

        base =
          if i.witness != [], do: Map.put(base, :witness, Enum.map(i.witness, &hex/1)), else: base

        inner_scripts(base, po, i)
      end)

    fee =
      if coinbase or Enum.any?(prevouts, &is_nil/1),
        do: 0,
        else:
          Enum.reduce(prevouts, 0, &(&2 + &1.value)) -
            Enum.reduce(tx.outputs, 0, &(&2 + &1.value))

    %{
      txid: Hash.to_hex(tx.txid),
      version: tx.version,
      locktime: tx.locktime,
      vin: vin,
      vout: Enum.map(tx.outputs, &out_json(opts, &1)),
      size: byte_size(tx.raw),
      weight: Tx.weight(tx),
      fee: fee,
      status: tx_status(opts, found)
    }
  end

  # electrs: inner_redeemscript_asm (P2SH) / inner_witnessscript_asm (P2WSH, P2SH-P2WSH).
  defp inner_scripts(base, nil, _i), do: base

  defp inner_scripts(base, po, i) do
    base =
      if Exnode.Script.p2sh?(po.script_pubkey) do
        case Policy.eval_push_only(i.script_sig) do
          {:ok, [_ | _] = stack} -> Map.put(base, :inner_redeemscript_asm, asm(List.last(stack)))
          _ -> base
        end
      else
        base
      end

    wsh =
      match?(<<0, 32, _::binary-size(32)>>, po.script_pubkey) or
        (Map.has_key?(base, :inner_redeemscript_asm) and
           match?({:ok, [_ | _]}, Policy.eval_push_only(i.script_sig)) and
           match?(<<0, 32, _::binary>>, List.last(elem(Policy.eval_push_only(i.script_sig), 1))))

    if wsh and i.witness != [],
      do: Map.put(base, :inner_witnessscript_asm, asm(List.last(i.witness))),
      else: base
  end

  defp out_json(opts, %Tx.Out{value: v, script_pubkey: spk}) do
    m = %{
      scriptpubkey: hex(spk),
      scriptpubkey_asm: asm(spk),
      scriptpubkey_type: script_type(spk),
      value: v
    }

    case Address.from_script(spk, network(opts)) do
      nil -> m
      a -> Map.put(m, :scriptpubkey_address, a)
    end
  end

  defp hex(b), do: Base.encode16(b, case: :lower)

  # electrs get_script_type
  defp script_type(<<>>), do: "empty"

  defp script_type(spk) do
    case Policy.solver(spk) do
      {:pubkey, _} ->
        "p2pk"

      {:pubkeyhash, _} ->
        "p2pkh"

      {:scripthash, _} ->
        "p2sh"

      {:witness_v0_keyhash, _} ->
        "v0_p2wpkh"

      {:witness_v0_scripthash, _} ->
        "v0_p2wsh"

      {:witness_v1_taproot, _} ->
        "v1_p2tr"

      _ ->
        cond do
          :binary.first(spk) == 0x6A -> "op_return"
          Exnode.Script.unspendable?(spk) -> "provably_unspendable"
          true -> "unknown"
        end
    end
  end

  @doc "rust-bitcoin `Script::to_asm_string` (as electrs prints scripts)."
  def asm(script), do: asm_loop(script, []) |> Enum.reverse() |> Enum.join(" ")

  defp asm_loop(<<>>, acc), do: acc

  defp asm_loop(<<op, rest::binary>> = s, acc) do
    case Exnode.Script.get_op(s) do
      :error ->
        ["<push past end>" | acc]

      {:ok, 0, _, r} ->
        asm_loop(r, ["OP_0" | acc])

      {:ok, o, d, r} when o < 0x4C ->
        asm_loop(r, [hex(d), "OP_PUSHBYTES_#{o}" | acc])

      {:ok, o, d, r} when o in [0x4C, 0x4D, 0x4E] ->
        name = %{0x4C => "OP_PUSHDATA1", 0x4D => "OP_PUSHDATA2", 0x4E => "OP_PUSHDATA4"}[o]
        asm_loop(r, [hex(d), name | acc])

      {:ok, _, _, r} ->
        _ = rest
        asm_loop(r, [op_name(op) | acc])
    end
  end

  defp op_name(0x4F), do: "OP_PUSHNUM_NEG1"
  defp op_name(op) when op >= 0x51 and op <= 0x60, do: "OP_PUSHNUM_#{op - 0x50}"
  defp op_name(0xB1), do: "OP_CLTV"
  defp op_name(0xB2), do: "OP_CSV"
  defp op_name(op) when op >= 0xBB and op <= 0xFE, do: "OP_RETURN_#{op}"
  defp op_name(op), do: Exnode.RPC.JSON.op_name(op)

  # Spenders in the mempool (one call), then on the chain (the archive's
  # spend records: one seek per output and one tx read per spending tx;
  # no address history, and no scripthash index needed).
  defp outspends(opts, tx) do
    ops = for v <- 0..(length(tx.outputs) - 1)//1, do: {tx.txid, v}
    mem = Mempool.spenders(ctx(opts).mempool, ops)
    chain = Archive.spenders(reader(opts), Enum.reject(ops, &Map.has_key?(mem, &1)))

    for op <- ops do
      case {mem[op], chain[op]} do
        {{spender, vin}, _} ->
          %{spent: true, txid: Hash.to_hex(spender), vin: vin, status: %{confirmed: false}}

        {nil, {spender, vin, header, pos}} ->
          found = {:block, nil, header, HeaderIndex.lookup(idx(opts), header.hash), pos}
          %{spent: true, txid: Hash.to_hex(spender), vin: vin, status: tx_status(opts, found)}

        {nil, nil} ->
          %{spent: false}
      end
    end
  end

  # Core-style merkle branch for tx `pos` (hex, display order).
  defp merkle_branch(b, pos) do
    level = Enum.map(b.txs, & &1.txid)
    branch(level, pos, []) |> Enum.map(&Hash.to_hex/1)
  end

  defp branch([_], _pos, acc), do: Enum.reverse(acc)

  defp branch(level, pos, acc) do
    level = if rem(length(level), 2) == 1, do: level ++ [List.last(level)], else: level
    sibling = Enum.at(level, Bitwise.bxor(pos, 1))
    next = level |> Enum.chunk_every(2) |> Enum.map(fn [a, b] -> Hash.hash256(a <> b) end)
    branch(next, div(pos, 2), [sibling | acc])
  end

  # --- address stats, history, utxos --------------------------------------------------

  defp with_script(conn, opts, {:address, a}, f) do
    case Address.to_script(a, network(opts)) do
      {:ok, spk} ->
        require_index(conn, opts, fn -> f.({Scripthash.scripthash(spk), spk}, %{address: a}) end)

      {:error, _} ->
        err(conn, 400, "Invalid Bitcoin address")
    end
  end

  defp with_script(conn, opts, {:scripthash, h}, f) do
    case byte_size(h) == 64 && Base.decode16(h, case: :mixed) do
      {:ok, sh} ->
        require_index(conn, opts, fn -> f.({sh, nil}, %{scripthash: String.downcase(h)}) end)

      _ ->
        err(conn, 400, "Invalid scripthash")
    end
  end

  defp require_index(conn, opts, f),
    do:
      if(ctx(opts)[:scripthash_index],
        do: f.(),
        else: err(conn, 400, "Address indexing is disabled")
      )

  # Confirmed history rows on the active chain, plus the mempool txs touching the script.
  defp confirmed(opts, {sh, _spk}), do: Scripthash.history(ctx(opts).scripthash_index, sh)

  # height => the active chain's header entry, for the heights of `rows`
  # whose indexed block is that one. Between a disconnect and the index's
  # rewind (≤ 200 ms) the index can hold rows above the tip, or of a block
  # no longer active: those heights are left out (the rows were skipped,
  # not answered with a 500 or another block's hash; SVC-3 in
  # STATE_MACHINES.md).
  defp active_index_blocks(opts, t, rows) do
    index = ctx(opts).scripthash_index

    for h <- rows |> Enum.map(& &1.height) |> Enum.uniq(),
        h <= t.height,
        e = HeaderIndex.ancestor(idx(opts), t, h),
        e != nil and Scripthash.hash_at(index, h) == e.hash,
        into: %{},
        do: {h, e}
  end

  # The mempool txs touching the script, oldest first, from the mempool's
  # script index (only those txs are copied out; the outputs they spend
  # come with them, so nothing is read from the archive).
  defp mempool_rows(opts, {sh, _spk}) do
    case Mempool.script_txs(ctx(opts).mempool, sh) do
      {:error, :not_indexed} ->
        raise "the mempool keeps no script index (start it with index_scripts: true)"

      txs ->
        for t <- txs do
          funding =
            for {o, v} <- Enum.with_index(t.tx.outputs),
                Scripthash.scripthash(o.script_pubkey) == sh,
                do: {v, o.value}

          spending =
            for {{i, {value, h}}, n} <- Enum.with_index(Enum.zip(t.tx.inputs, t.spent)),
                h == sh,
                do: {n, value, {i.prev_hash, i.prev_index}}

          %{txid: t.txid, tx: t.tx, funding: funding, spending: spending}
        end
    end
  end

  defp stats(opts, script, label) do
    mem = mempool_rows(opts, script)
    mf = Enum.flat_map(mem, & &1.funding)
    ms = Enum.flat_map(mem, & &1.spending)

    Map.merge(label, %{
      chain_stats: chain_stats(opts, script),
      mempool_stats: %{
        funded_txo_count: length(mf),
        funded_txo_sum: Enum.reduce(mf, 0, &(&2 + elem(&1, 1))),
        spent_txo_count: length(ms),
        spent_txo_sum: Enum.reduce(ms, 0, &(&2 + elem(&1, 1))),
        tx_count: length(mem)
      }
    })
  end

  # The index's per-script totals (five point reads). While an index built
  # before them is still getting them, the same figures from the history.
  defp chain_stats(opts, {sh, _} = script) do
    Scripthash.totals(ctx(opts).scripthash_index, sh) ||
      (
        rows = confirmed(opts, script)
        fund = Enum.filter(rows, &(&1.kind == :funding))
        spend = Enum.filter(rows, &(&1.kind == :spending))

        %{
          funded_txo_count: length(fund),
          funded_txo_sum: Enum.reduce(fund, 0, &(&2 + &1.value)),
          spent_txo_count: length(spend),
          spent_txo_sum: Enum.reduce(spend, 0, &(&2 + &1.value)),
          tx_count: rows |> Enum.map(&{&1.height, &1.pos}) |> Enum.uniq() |> length()
        }
      )
  end

  # Esplora: up to 50 mempool txs, then the first 25 confirmed (newest first);
  # /txs/chain/:last continues after last_seen_txid.
  # Only the page's rows are read: from the newest, or from below the last
  # seen tx (none if that tx is not in the history; an unparsable one reads
  # from the newest).
  defp txs_page(opts, {sh, _} = script, last, include_mempool) do
    mem =
      if include_mempool,
        do: opts |> mempool_rows(script) |> Enum.take(50) |> Enum.map(&{:mempool, &1.tx}),
        else: []

    start =
      case last && parse_hash(last) do
        {:ok, h} -> cursor(opts, sh, h)
        _ -> nil
      end

    chain_txids =
      if start == :none,
        do: [],
        else:
          Scripthash.history_page(ctx(opts).scripthash_index, sh, start, 25)
          |> Enum.map(&{&1.height, &1.pos, &1.txid})
          |> Enum.uniq()
          |> Enum.map(&elem(&1, 2))

    # Two mempool calls for the page: its confirmed txs (normally none is
    # in the mempool), then the txs its inputs spend.
    in_mempool = mempool_txs(opts, chain_txids, nil)
    page = mem ++ Enum.map(chain_txids, &find_tx(opts, &1, in_mempool))

    known =
      mempool_txs(opts, for(f <- page, i <- tx_of(f).inputs, uniq: true, do: i.prev_hash), nil)

    Enum.map(page, &tx_json(opts, &1, known))
  end

  # `{height, pos}` of a tx in the script's confirmed history, or :none.
  defp cursor(opts, sh, txid) do
    a = reader(opts)

    with {:ok, id, pos} <- Archive.tx_location(a, txid),
         true <- Archive.on_chain?(a, id),
         h = Archive.block_record!(a, id).height,
         true <-
           Enum.any?(
             Scripthash.rows_at(ctx(opts).scripthash_index, sh, {h, pos}),
             &(&1.txid == txid)
           ) do
      {h, pos}
    else
      _ -> :none
    end
  end

  defp utxos(opts, script) do
    rows = confirmed(opts, script)
    spent = MapSet.new(for r <- rows, r.kind == :spending, do: r.prevout)
    mem = mempool_rows(opts, script)
    mem_spent = MapSet.new(for m <- mem, {_, _, op} <- m.spending, do: op)
    t = tip_entry(opts)
    active = active_index_blocks(opts, t, rows)

    confirmed_utxos =
      for r <- rows,
          r.kind == :funding,
          op = {r.txid, r.index},
          not MapSet.member?(spent, op),
          not MapSet.member?(mem_spent, op),
          e = active[r.height],
          e != nil do
        %{
          txid: Hash.to_hex(r.txid),
          vout: r.index,
          value: r.value,
          status: %{
            confirmed: true,
            block_height: r.height,
            block_hash: Hash.to_hex(e.hash),
            block_time: e.time
          }
        }
      end

    mempool_utxos =
      for m <- mem,
          {v, value} <- m.funding,
          not MapSet.member?(mem_spent, {m.txid, v}),
          do: %{txid: Hash.to_hex(m.txid), vout: v, value: value, status: %{confirmed: false}}

    confirmed_utxos ++ mempool_utxos
  end
end
