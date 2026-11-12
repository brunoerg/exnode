defmodule Exnode.P2P.AddrRate do
  @moduledoc """
  Per-peer address rate limit. Port of Core v32.1 `net_processing.cpp`
  `ProcessAddrs` (`m_addr_token_bucket`): a peer starts with 1 token, gains
  `MAX_ADDR_RATE_PER_SECOND` (0.1) per second up to
  `MAX_ADDR_PROCESSING_TOKEN_BUCKET` (1000), and gets `MAX_ADDR_TO_SEND`
  (1000) more, above that cap, when we send it `getaddr`. Each address of a
  received `addr`/`addrv2` (in random order) costs one token; addresses
  past the tokens are dropped. Times are milliseconds.
  """

  @rate_per_s 0.1
  @cap 1000.0
  @getaddr_bonus 1000.0

  defstruct tokens: 1.0, at: nil

  def new(now_ms), do: %__MODULE__{at: now_ms}

  @doc "We sent `getaddr`: room for one full reply."
  def getaddr_sent(%__MODULE__{} = r), do: %{r | tokens: r.tokens + @getaddr_bonus}

  @doc "Applies the bucket to a received address list: `{rate, accepted, n_rate_limited}`."
  def received(%__MODULE__{} = r, addrs, now_ms) do
    tokens =
      if r.tokens < @cap,
        do: min(r.tokens + max(now_ms - r.at, 0) / 1000 * @rate_per_s, @cap),
        else: r.tokens

    {tokens, acc, limited} =
      addrs
      |> Enum.shuffle()
      |> Enum.reduce({tokens, [], 0}, fn a, {t, acc, lim} ->
        if t < 1.0, do: {t, acc, lim + 1}, else: {t - 1.0, [a | acc], lim}
      end)

    {%{r | tokens: tokens, at: now_ms}, Enum.reverse(acc), limited}
  end
end
