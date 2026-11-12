defmodule Exnode.Test.EsploraOracle do
  @moduledoc """
  The Esplora router as it was before fix-03 WS3 (lib/exnode/rest/esplora.ex
  at commit 8cc50c4), kept verbatim as the oracle for
  `Exnode.REST.EsploraTest`: the new router must answer with the same JSON
  at a fraction of the cost. Its history scans go through the current
  `Scripthash.history/2` (same rows, read in the caller).
  """

  use Plug.Router, copy_opts_to_assign: :opts

  alias Exnode.{Address, Archive, Mempool}
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Index.Scripthash
  alias Exnode.Mempool.Policy

  plug(:match)
  plug(:dispatch)

  def child_spec(opts) do
    Supervisor.child_spec(
      {Bandit,
       plug: {__MODULE__, %{ctx: Keyword.fetch!(opts, :ctx)}},
       port: Keyword.fetch!(opts, :port),
       ip: Keyword.get(opts, :ip, {127, 0, 0, 1}),
       startup_log: false},
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
      {:block, _tx, b, e, pos} ->
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
    pool = Mempool.pool(conn.assigns.opts.ctx.mempool)
    entries = Map.values(pool.entries)

    hist =
      entries
      |> Enum.map(&{&1.fee / &1.vsize, &1.vsize})
      |> Enum.sort(:desc)
      |> Enum.chunk_by(fn {r, _} -> round(r * 10) end)
      |> Enum.map(fn group ->
        [elem(hd(group), 0), Enum.reduce(group, 0, &(&2 + elem(&1, 1)))]
      end)

    json(conn, %{
      count: length(entries),
      vsize: pool.total_vsize,
      total_fee: Enum.reduce(entries, 0, &(&2 + &1.fee)),
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

  # A tx: {:mempool, tx} or {:block, tx, block, header_entry, pos}.
  defp with_tx(conn, opts, t, f) do
    with {:ok, txid} <- parse_hash(t),
         found when found != nil <- find_tx(opts, txid) do
      f.(found)
    else
      _ -> err(conn, 404, "Transaction not found")
    end
  end

  defp find_tx(opts, txid) do
    case Mempool.get_tx(ctx(opts).mempool, txid) do
      %Tx{} = tx ->
        {:mempool, tx}

      nil ->
        a = reader(opts)

        case Archive.tx_location(a, txid) do
          :missing ->
            nil

          {:ok, id, pos} ->
            {:ok, b} = Archive.read_block_txs(a, id)
            {:block, Enum.at(b.txs, pos), b, HeaderIndex.lookup(idx(opts), b.header.hash), pos}
        end
    end
  end

  defp tx_of({:mempool, tx}), do: tx
  defp tx_of({:block, tx, _, _, _}), do: tx

  defp tx_status(_opts, {:mempool, _}), do: %{confirmed: false}

  defp tx_status(opts, {:block, _, b, e, _}) do
    if active?(opts, e),
      do: %{
        confirmed: true,
        block_height: e.height,
        block_hash: Hash.to_hex(e.hash),
        block_time: b.header.time
      },
      else: %{confirmed: false}
  end

  # The output a tx input spends (mempool first, then the archive).
  defp prevout(opts, txid, vout) do
    case Mempool.get_tx(ctx(opts).mempool, txid) do
      %Tx{outputs: outs} ->
        Enum.at(outs, vout)

      nil ->
        case find_tx(opts, txid) do
          {:block, tx, _, _, _} -> Enum.at(tx.outputs, vout)
          _ -> nil
        end
    end
  end

  defp tx_json(opts, found) do
    tx = tx_of(found)
    coinbase = Tx.coinbase?(tx)

    prevouts =
      if coinbase, do: [], else: Enum.map(tx.inputs, &prevout(opts, &1.prev_hash, &1.prev_index))

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

  defp outspends(opts, tx) do
    pool = Mempool.pool(ctx(opts).mempool)

    for v <- 0..(length(tx.outputs) - 1)//1 do
      case Exnode.Mempool.Pool.spender(pool, {tx.txid, v}) do
        nil ->
          case chain_spender(opts, tx, v) do
            nil ->
              %{spent: false}

            {spending_txid, vin, found} ->
              %{
                spent: true,
                txid: Hash.to_hex(spending_txid),
                vin: vin,
                status: tx_status(opts, found)
              }
          end

        spender ->
          e = Exnode.Mempool.Pool.get(pool, spender)
          vin = Enum.find_index(e.tx.inputs, &(&1.prev_hash == tx.txid and &1.prev_index == v))
          %{spent: true, txid: Hash.to_hex(spender), vin: vin, status: %{confirmed: false}}
      end
    end
  end

  # The confirmed spender of tx:v, via the scripthash index of the output's script.
  defp chain_spender(opts, tx, v) do
    with idx when idx != nil <- ctx(opts)[:scripthash_index],
         o = Enum.at(tx.outputs, v),
         rows = Scripthash.history(idx, Scripthash.scripthash(o.script_pubkey)),
         %{} = row <- Enum.find(rows, &(&1.kind == :spending and &1.prevout == {tx.txid, v})) do
      {row.txid, row.index, find_tx(opts, row.txid)}
    else
      _ -> nil
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

  defp mempool_rows(opts, {sh, _spk}) do
    pool = Mempool.pool(ctx(opts).mempool)

    pool.entries
    |> Enum.map(fn {txid, e} ->
      funding =
        for {o, v} <- Enum.with_index(e.tx.outputs),
            Scripthash.scripthash(o.script_pubkey) == sh,
            do: {v, o.value}

      spending =
        for {i, n} <- Enum.with_index(e.tx.inputs),
            po = prevout(opts, i.prev_hash, i.prev_index),
            po != nil and Scripthash.scripthash(po.script_pubkey) == sh,
            do: {n, po.value, {i.prev_hash, i.prev_index}}

      %{txid: txid, funding: funding, spending: spending, entry: e}
    end)
    |> Enum.filter(&(&1.funding != [] or &1.spending != []))
    |> Enum.sort_by(& &1.entry.sequence)
  end

  defp stats(opts, script, label) do
    rows = confirmed(opts, script)
    mem = mempool_rows(opts, script)
    fund = Enum.filter(rows, &(&1.kind == :funding))
    spend = Enum.filter(rows, &(&1.kind == :spending))
    mf = Enum.flat_map(mem, & &1.funding)
    ms = Enum.flat_map(mem, & &1.spending)

    Map.merge(label, %{
      chain_stats: %{
        funded_txo_count: length(fund),
        funded_txo_sum: Enum.reduce(fund, 0, &(&2 + &1.value)),
        spent_txo_count: length(spend),
        spent_txo_sum: Enum.reduce(spend, 0, &(&2 + &1.value)),
        tx_count: rows |> Enum.map(& &1.txid) |> Enum.uniq() |> length()
      },
      mempool_stats: %{
        funded_txo_count: length(mf),
        funded_txo_sum: Enum.reduce(mf, 0, &(&2 + elem(&1, 1))),
        spent_txo_count: length(ms),
        spent_txo_sum: Enum.reduce(ms, 0, &(&2 + elem(&1, 1))),
        tx_count: length(mem)
      }
    })
  end

  # Esplora: up to 50 mempool txs, then the first 25 confirmed (newest first);
  # /txs/chain/:last continues after last_seen_txid.
  defp txs_page(opts, script, last, include_mempool) do
    mem =
      if include_mempool,
        do: opts |> mempool_rows(script) |> Enum.take(50) |> Enum.map(&{:mempool, &1.entry.tx}),
        else: []

    chain_txids =
      opts
      |> confirmed(script)
      |> Enum.map(&{&1.height, &1.pos, &1.txid})
      |> Enum.uniq()
      |> Enum.sort(:desc)
      |> Enum.map(&elem(&1, 2))

    chain_txids =
      case last && parse_hash(last) do
        {:ok, h} -> chain_txids |> Enum.drop_while(&(&1 != h)) |> Enum.drop(1)
        _ -> chain_txids
      end

    chain = chain_txids |> Enum.take(25) |> Enum.map(&find_tx(opts, &1))
    Enum.map(mem ++ chain, &tx_json(opts, &1))
  end

  defp utxos(opts, script) do
    rows = confirmed(opts, script)
    spent = MapSet.new(for r <- rows, r.kind == :spending, do: r.prevout)
    mem = mempool_rows(opts, script)
    mem_spent = MapSet.new(for m <- mem, {_, _, op} <- m.spending, do: op)
    t = tip_entry(opts)

    confirmed_utxos =
      for r <- rows,
          r.kind == :funding,
          op = {r.txid, r.index},
          not MapSet.member?(spent, op),
          not MapSet.member?(mem_spent, op) do
        e = HeaderIndex.ancestor(idx(opts), t, r.height)

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
