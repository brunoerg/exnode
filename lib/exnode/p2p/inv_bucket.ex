defmodule Exnode.P2P.InvBucket do
  @moduledoc """
  Transaction announcement rate limit. Port of Core v32.1
  `net_processing.cpp` `InvToSendBucket` and `util/tokenbucket.h`
  `TokenBucket`.

  One bucket for inbound peers, one for outbound (rate × 2.5, Core
  `OUTBOUND_INVENTORY_BUCKET_MULTIPLIER` = 5 s / 2 s). New mempool txs go
  into a global backlog; every 100 ms (and when the backlog grows) the
  bucket refills and releases the best backlog txs by mining score while it
  has tokens:
  * count bucket: `rate` tokens/s (Core `DEFAULT_TX_SEND_RATE` 14) × mult,
    starting full at `rate × 30`, capped there; may go down to
    `-rate × 5` (one average INV's worth) on a release;
  * size bucket: 20 kB/s × mult, starting at 12 MB, capped at 50 MB; may go
    down to -50 kB.
  The tx that runs a bucket out is still released; the rest stay.

  Times are milliseconds.
  """

  alias Exnode.Util.TokenBucket

  @default_rate 14
  @outbound_mult 5.0 / 2.0
  @size_init 12_000_000.0
  @size_cap 50_000_000.0
  @size_refill 20_000.0
  @size_floor -50_000.0
  @inbound_count_seconds 30
  @inbound_broadcast_interval_s 5

  def default_rate, do: @default_rate
  def outbound_mult, do: @outbound_mult

  @doc "Core `InvToSendBucket(rate, mult)`."
  def new(rate, mult) do
    %{
      backlog: [],
      count_floor: -1.0 * rate * @inbound_broadcast_interval_s,
      size: TokenBucket.new(@size_refill * mult, @size_init, @size_cap),
      count:
        TokenBucket.new(rate * mult, rate * @inbound_count_seconds, rate * @inbound_count_seconds)
    }
  end

  def push(b, txid), do: %{b | backlog: [txid | b.backlog]}
  def backlog(b), do: b.backlog
  def clear(b), do: %{b | backlog: []}
  def tokens(b), do: {b.count.value, b.size.value}

  @doc "Core `InvToSendBucket::increment` (both token buckets)."
  def increment(b, now),
    do: %{
      b
      | size: TokenBucket.increment(b.size, now),
        count: TokenBucket.increment(b.count, now)
    }

  @doc """
  Core `avail()` + `TakeForProcessing`. `extract.(txids, n)` returns the
  best `n` as `[{txid, total_size}]` in mining order and the remaining
  txids (Core `ExtractBestByMiningScoreWithTopology`). Returns
  `{bucket, released_txids}`.
  """
  def take(b, extract) do
    if b.backlog != [] and b.size.value > 0 and b.count.value > 0 do
      n = trunc(max(b.count.value - b.count_floor, 0))
      {best, rest} = extract.(b.backlog, n)

      {b, out, _} =
        Enum.reduce(best, {%{b | backlog: rest}, [], true}, fn {txid, size},
                                                               {b, out, tokens_left} ->
          if tokens_left do
            {sb, size_ok} = TokenBucket.decrement(b.size, size, @size_floor)
            {cb, count_ok} = TokenBucket.decrement(b.count, 1, b.count_floor)
            {%{b | size: sb, count: cb}, [txid | out], size_ok and count_ok}
          else
            {%{b | backlog: [txid | b.backlog]}, out, false}
          end
        end)

      {b, Enum.reverse(out)}
    else
      {b, []}
    end
  end
end
