defmodule Exnode.Crypto.Secp do
  @moduledoc """
  ElligatorSwift ECDH for BIP324, through `native/secp_nif` on the
  libsecp256k1 pinned with Core v32.1. Mirrors Core key.cpp
  `CKey::EllSwiftCreate` and `CKey::ComputeBIP324ECDHSecret`.

  Sizes are checked here and again in the NIF; the secret key is checked
  with `secp256k1_ec_seckey_verify` before every use.
  """
  @on_load :load_nif

  @doc false
  def load_nif do
    path = :filename.join(:code.priv_dir(:exnode), ~c"native/secp_nif")
    :erlang.load_nif(path, 0)
  end

  @doc """
  A fresh ephemeral key: `{seckey32, ellswift64}` (Core `GenerateRandomKey`
  then `EllSwiftCreate` with 32 random bytes of entropy). `rand` returns
  that many random bytes (default `:crypto.strong_rand_bytes/1`).
  """
  def new_ellswift_key(rand \\ &:crypto.strong_rand_bytes/1) do
    sk = rand.(32)

    case ellswift_create(sk, rand.(32)) do
      {:ok, ell} -> {sk, ell}
      # Not a valid key (zero or >= the group order): draw again.
      :error -> new_ellswift_key(rand)
    end
  end

  @doc "`{:ok, ell64}` for `seckey32`, or `:error` if the key is invalid."
  def ellswift_create(<<_::256>> = sk, <<_::256>> = aux), do: create_nif(sk, aux)

  @doc """
  Core `ComputeBIP324ECDHSecret`: the BIP324 x-only ECDH secret. The
  initiator is party A: its key goes first and it passes party 0.
  """
  def bip324_ecdh(<<_::256>> = sk, <<_::512>> = ours, <<_::512>> = theirs, initiating)
      when is_boolean(initiating) do
    {a, b} = if initiating, do: {ours, theirs}, else: {theirs, ours}
    xdh_nif(a, b, sk, if(initiating, do: 0, else: 1))
  end

  @doc "The compressed public key a 64-byte ElligatorSwift encoding decodes to."
  def ellswift_decode(<<_::512>> = ell), do: decode_nif(ell)

  # NIF entry points (replaced at load).
  @doc false
  def create_nif(_sk, _aux), do: :erlang.nif_error(:nif_not_loaded)
  @doc false
  def xdh_nif(_a, _b, _sk, _party), do: :erlang.nif_error(:nif_not_loaded)
  @doc false
  def decode_nif(_ell), do: :erlang.nif_error(:nif_not_loaded)
end
