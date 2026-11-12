# Controlled P2P sync (block download measurements): in-VM fake peers
# serve an export's headers and blocks (scripts/replay_export.exs format)
# over loopback to a real Exnode.Node, which syncs them as in IBD (its own
# headers sync, BlockDownload, peers' CheckBlock, deferred submission).
#
# Usage (from the exnode tree to measure):
#   mix run scripts/p2p_replay.exs <export_dir> <fresh_datadir> <n_peers> <label>
# <fresh_datadir> is deleted first. Optional environment:
#   P2P_LATENCY_MS   delay before each getdata reply, per peer (default 0)
#   P2P_REORDER=1    peers answer each getdata in reverse order
#   P2P_SLOW_PEER=ms one peer (the first) adds this extra delay per block
#   P2P_ASSUMEVALID  passed to the node (default: the chain's)
#   P2P_DEADLINE_S   whole-run limit (default 1800)
#   P2P_ANNOUNCE=0   peers do not announce their tip after the handshake (then
#                    only the headers-sync peer serves blocks, as in Core's IBD
#                    with an old best header)
#
# The fake peers count every block request (duplicates are requests for a
# block already requested before, from any peer) and the bytes served. The
# node's tip is sampled every 100 ms: an "ancestor stall" is an interval of
# at least 1 s without tip progress while blocks remain. Fails (exit 1) on
# a halt, a quarantine, the deadline, or a final tip other than the last
# exported block.
alias Exnode.ChainParams
alias Exnode.Chain.State
alias Exnode.Codec.Header
alias Exnode.P2P.{Frame, Message}

require Logger
Logger.configure(level: :warning)

[export, datadir, n_peers, label] = System.argv()
n_peers = String.to_integer(n_peers)
p = ChainParams.get(:testnet4)
latency = String.to_integer(System.get_env("P2P_LATENCY_MS", "0"))
reorder = System.get_env("P2P_REORDER") == "1"
slow = String.to_integer(System.get_env("P2P_SLOW_PEER", "0"))
deadline_s = String.to_integer(System.get_env("P2P_DEADLINE_S", "1800"))

read_records = fn path ->
  {:ok, bin} = File.read(path)
  Stream.unfold(bin, fn
    <<n::32, rec::binary-size(n), rest::binary>> -> {rec, rest}
    _ -> nil
  end)
end

blocks = Enum.to_list(read_records.(Path.join(export, "blocks.bin")))
n_blocks = length(blocks)
# Every exported header (to the copy's best): the node's anti-DoS headers
# sync needs a chain with minimum_chain_work. Blocks only to `n_blocks`:
# above it the peers answer notfound, and the run ends at the last block.
headers =
  read_records.(Path.join(export, "headers.bin"))
  |> Enum.map(fn raw -> {h, <<>>} = Header.decode(raw); h end)

by_hash = :ets.new(:blocks, [:set, :public, read_concurrency: true])
for {h, raw} <- Enum.zip(Enum.take(headers, n_blocks), blocks), do: :ets.insert(by_hash, {h.hash, raw})
hdr_index = Map.new(Enum.with_index(headers), fn {h, i} -> {h.hash, i} end)
hdr_tuple = List.to_tuple(headers)
terminal = Enum.at(headers, n_blocks - 1).hash
bytes_total = Enum.reduce(blocks, 0, &(&2 + byte_size(&1)))

# Request accounting: hash => times requested; per-peer requested blocks and bytes.
requests = :ets.new(:requests, [:set, :public, write_concurrency: true])
magic = p.magic

defmodule FakeServer do
  import Bitwise
  def serve(lsock, ctx, i) do
    {:ok, sock} = :gen_tcp.accept(lsock)
    :ok = :inet.setopts(sock, [nodelay: true])
    loop(sock, ctx, i, <<>>)
  end

  defp send_msgs(sock, magic, msgs) do
    bin =
      for m <- msgs, into: <<>> do
        {c, pl} = Exnode.P2P.Message.encode(m)
        IO.iodata_to_binary(Exnode.P2P.Frame.encode(magic, c, pl))
      end

    :gen_tcp.send(sock, bin)
  end

  defp loop(sock, ctx, i, buf) do
    case Exnode.P2P.Frame.decode(ctx.magic, buf) do
      {:ok, cmd, payload, rest} ->
        handle(sock, ctx, i, cmd, payload)
        loop(sock, ctx, i, rest)

      _ ->
        case :gen_tcp.recv(sock, 0) do
          {:ok, data} -> loop(sock, ctx, i, buf <> data)
          {:error, _} -> :ok
        end
    end
  end

  defp handle(sock, ctx, i, cmd, payload) do
    case Exnode.P2P.Message.decode(cmd, payload) do
      {:ok, {:version, _}} ->
        v = %{
          version: 70016,
          services: 9,
          time: System.os_time(:second),
          addr_recv: %{services: 0, net: :ipv4, addr: <<127, 0, 0, 1>>, port: 0},
          nonce: :rand.uniform(1 <<< 60),
          user_agent: "/p2p_replay/",
          start_height: ctx.n,
          relay: false
        }

        send_msgs(sock, ctx.magic, [{:version, v}, :verack])

      {:ok, :verack} ->
        # Announce our tip, as a peer at the tip does: the node learns this
        # peer's best chain (and fetches the headers it lacks from it), so
        # every peer can serve blocks, not only the headers-sync peer.
        if ctx.announce, do: send_msgs(sock, ctx.magic, [{:headers, [elem(ctx.hdrs, ctx.n - 1)]}])

      {:ok, {:ping, nonce}} ->
        send_msgs(sock, ctx.magic, [{:pong, nonce}])

      {:ok, {:getheaders, %{locator: loc}}} ->
        start = Enum.find_value(loc, -1, &Map.get(ctx.hdr_index, &1))
        hs = for k <- (start + 1)..min(start + 2_000, ctx.n - 1)//1, do: elem(ctx.hdrs, k)
        send_msgs(sock, ctx.magic, [{:headers, hs}])

      {:ok, {:getdata, items}} ->
        if ctx.latency > 0, do: Process.sleep(ctx.latency)
        items = if ctx.reorder, do: Enum.reverse(items), else: items

        for %{type: :block, hash: h} <- items do
          if i == 0 and ctx.slow > 0, do: Process.sleep(ctx.slow)
          :ets.update_counter(ctx.requests, h, {2, 1}, {h, 0})

          case :ets.lookup(ctx.blocks, h) do
            [{_, raw}] ->
              :ets.update_counter(ctx.requests, {:peer, i}, [{2, 1}, {3, byte_size(raw)}], {{:peer, i}, 0, 0})
              send_msgs(sock, ctx.magic, [{:block, raw}])

            [] ->
              send_msgs(sock, ctx.magic, [{:notfound, [%{type: :block, hash: h}]}])
          end
        end

      _ ->
        :ok
    end
  end
end

ctx = %{
  magic: magic,
  n: length(headers),
  hdrs: hdr_tuple,
  hdr_index: hdr_index,
  blocks: by_hash,
  requests: requests,
  latency: latency,
  reorder: reorder,
  slow: slow,
  announce: System.get_env("P2P_ANNOUNCE", "1") == "1"
}

ports =
  for i <- 0..(n_peers - 1) do
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(lsock)
    spawn(fn -> FakeServer.serve(lsock, ctx, i) end)
    port
  end

File.rm_rf!(datadir)
name = :"P2PReplay#{System.unique_integer([:positive])}"
av = if a = System.get_env("P2P_ASSUMEVALID"), do: [assume_valid: a], else: []

t0 = System.monotonic_time(:millisecond)

{:ok, _sup} =
  Exnode.Node.start_link(
    [
      name: name,
      chain: :testnet4,
      datadir: datadir,
      connect: for(port <- ports, do: {"127.0.0.1", port}),
      v2_transport: false,
      cache_bytes: 0
    ] ++ av
  )

n = Exnode.Node.names(name)
view = fn -> State.view(n.chain_state) end
deadline = t0 + deadline_s * 1000

fail = fn why ->
  IO.puts(:stderr, "P2P REPLAY FAILED (#{label}): #{why}")
  System.halt(1)
end

# Samples the tip every 100 ms until it is the terminal block.
sample = fn sample, last_h, last_t, stalls, stall_ms ->
  now = System.monotonic_time(:millisecond)
  v = view.()
  tip = v && State.view_tip(v)
  h = (tip && tip.height) || 0

  cond do
    v && State.view_halted(v) != false -> fail.("halted: #{inspect(State.view_halted(v))}")
    tip && tip.hash == terminal -> {now, stalls, stall_ms}
    now > deadline -> fail.("deadline at height #{h}")
    h > last_h -> (Process.sleep(100); sample.(sample, h, now, stalls, stall_ms))
    true ->
      {stalls, stall_ms, last_t} =
        if now - last_t >= 1_000,
          do: {stalls + 1, stall_ms + (now - last_t), now},
          else: {stalls, stall_ms, last_t}

      Process.sleep(100)
      sample.(sample, last_h, last_t, stalls, stall_ms)
  end
end

{t_tip, stalls, stall_ms} = sample.(sample, -1, t0, 0, 0)
:ok = State.commit_now(n.chain_state)
t_end = System.monotonic_time(:millisecond)

if State.poisoned(n.chain_state) != [], do: fail.("quarantined blocks")
if State.tip(n.chain_state).hash != terminal, do: fail.("final tip is not the last exported block")

counts = for {h, c} <- :ets.tab2list(requests), is_binary(h), do: c
requested = Enum.sum(counts)
per_peer = for {{:peer, i}, c, b} <- :ets.tab2list(requests), into: %{}, do: {i, %{blocks: c, bytes: b}}

bd =
  try do
    Exnode.P2P.BlockDownload.stats(n.block_download)
  catch
    _, _ -> nil
  end

w = State.work_stats(n.chain_state)

IO.puts(
  inspect(
    %{
      label: label,
      peers: n_peers,
      latency_ms: latency,
      reorder: reorder,
      slow_peer_ms: slow,
      blocks: n_blocks,
      block_bytes: bytes_total,
      terminal: Exnode.Crypto.Hash.to_hex(terminal),
      elapsed_tip_ms: t_tip - t0,
      elapsed_ms: t_end - t0,
      useful_mib_per_s: Float.round(bytes_total / 1_048_576 / ((t_end - t0) / 1000), 2),
      blocks_requested: requested,
      # Requests above the exported blocks (the window runs past them).
      beyond_export: Enum.count(:ets.tab2list(requests), fn
        {h, _} when is_binary(h) -> :ets.lookup(by_hash, h) == []
        _ -> false
      end),
      duplicate_requests: requested - length(counts),
      ancestor_stalls: stalls,
      ancestor_stall_ms: stall_ms,
      per_peer: per_peer,
      block_download: bd,
      pipeline: Map.get(w, :pipeline)
    },
    limit: :infinity,
    printable_limit: :infinity
  )
)

System.halt(0)
