defmodule Exnode.P2P.FilterServing do
  @moduledoc """
  BIP157 compact block filter serving (`getcfilters`, `getcfheaders`,
  `getcfcheckpt`), mirroring Core v32.1 `PrepareBlockFilterRequest` and filter
  message handlers in `net_processing.cpp`.
  """

  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Index.BlockFilter
  alias Exnode.P2P.{Message, Peer}

  @max_getcfilters 1000
  @max_getcfheaders 2000
  @cfcheckpt_interval 1000

  @doc "Serves a `getcfilters` request."
  def serve_cfilters(st, %{filter_type: t, start_height: start, stop_hash: stop_hash}) do
    with {:ok, idx, stop} <- filter_request(st, t, start, stop_hash, @max_getcfilters) do
      case filters_for(st, idx, stop, start) do
        :not_indexed ->
          {:ok, st}

        pairs ->
          {:ok,
           Enum.reduce(pairs, st, fn {e, {:ok, f, _}}, acc ->
             Peer.push(acc, {:cfilter, %{filter_type: 0, block_hash: e.hash, filter: f}})
           end)}
      end
    end
  end

  @doc "Serves a `getcfheaders` request."
  def serve_cfheaders(st, %{filter_type: t, start_height: start, stop_hash: stop_hash}) do
    with {:ok, idx, stop} <- filter_request(st, t, start, stop_hash, @max_getcfheaders) do
      # Filter hashes and headers only (never the filters),
      # the previous header in the same RocksDB multi_get.
      blocks = for h <- max(start - 1, 0)..stop.height//1, do: HeaderIndex.ancestor(idx, stop, h)

      results =
        BlockFilter.get_headers(st.node.filter_index, Enum.map(blocks, & &1.hash))

      case if(:not_found in results, do: :not_indexed, else: results) do
        pairs when is_list(pairs) ->
          {prev_header, pairs} =
            if start == 0,
              do: {<<0::256>>, pairs},
              else: (fn [{:ok, _, h} | rest] -> {h, rest} end).(pairs)

          hashes = for {:ok, fh, _} <- pairs, do: fh

          {:ok,
           Peer.push(
             st,
             {:cfheaders,
              %{
                filter_type: 0,
                stop_hash: stop.hash,
                prev_header: prev_header,
                filter_hashes: hashes
              }}
           )}

        _ ->
          {:ok, st}
      end
    end
  end

  @doc "Serves a `getcfcheckpt` request."
  def serve_cfcheckpt(st, %{filter_type: t, stop_hash: stop_hash}) do
    with {:ok, idx, stop} <- filter_request(st, t, 0, stop_hash, 0x1_0000_0000) do
      n = div(stop.height, @cfcheckpt_interval)

      hashes = for i <- 1..n//1, do: HeaderIndex.ancestor(idx, stop, i * @cfcheckpt_interval).hash

      headers =
        BlockFilter.get_headers(st.node.filter_index, hashes)
        |> Enum.map(fn
          {:ok, _, h} -> h
          :not_found -> nil
        end)

      if Enum.any?(headers, &is_nil/1),
        do: {:ok, st},
        else:
          {:ok,
           Peer.push(st, {:cfcheckpt, %{filter_type: 0, stop_hash: stop.hash, headers: headers}})}
    end
  end

  # Core PrepareBlockFilterRequest: basic filters only, and only with
  # NODE_COMPACT_FILTERS; a known stop block; a valid, bounded range.
  # Violations disconnect the peer.
  defp filter_request(st, type, start, stop_hash, max_diff) do
    idx = Headers.index(st.node.headers)
    stop = HeaderIndex.lookup(idx, stop_hash)

    cond do
      type != 0 or Bitwise.band(st.node.services, Message.service(:compact_filters)) == 0 or
          st.node[:filter_index] == nil ->
        {:stop, {:shutdown, :unsupported_filter_type}, st}

      stop == nil ->
        {:stop, {:shutdown, :invalid_filter_stop_hash}, st}

      start > stop.height ->
        {:stop, {:shutdown, :invalid_filter_range}, st}

      stop.height - start >= max_diff ->
        {:stop, {:shutdown, :too_many_filters_requested}, st}

      true ->
        {:ok, idx, stop}
    end
  end

  defp filters_for(st, idx, stop, start) do
    blocks = for h <- start..stop.height//1, do: HeaderIndex.ancestor(idx, stop, h)
    results = BlockFilter.get_many(st.node.filter_index, Enum.map(blocks, & &1.hash))
    if Enum.any?(results, &(&1 == :not_found)), do: :not_indexed, else: Enum.zip(blocks, results)
  end
end
