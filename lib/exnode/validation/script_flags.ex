defmodule Exnode.Validation.ScriptFlags do
  @moduledoc """
  Per-block script verification flags. Port of Core v32.1 `GetBlockScriptFlags`
  (validation.cpp).

  The result is a kernel flag bitfield (`Exnode.Kernel.flags/0`). Every flag
  Core sets here is a consensus flag the kernel exposes.
  """
  alias Exnode.ChainParams
  alias Exnode.Kernel

  @doc """
  Core `GetBlockScriptFlags(const CBlockIndex& block_index, const ChainstateManager& chainman)`.

  `height` and `hash` (internal byte order) identify the block being validated.
  """
  # Core: GetBlockScriptFlags (validation.cpp)
  @spec block_flags(ChainParams.t(), non_neg_integer(), binary()) :: non_neg_integer()
  def block_flags(%ChainParams{} = p, height, <<_::binary-size(32)>> = hash) do
    # P2SH + WITNESS + TAPROOT are always on, except for the blocks listed in
    # script_flag_exceptions (chainparams.cpp).
    base = Map.get(p.script_flag_exceptions, hash, [:p2sh, :witness, :taproot])

    # Buried deployments: DeploymentActiveAt(index, DEPLOYMENT_X) is
    # index.nHeight >= DeploymentHeight(X) (deploymentstatus.h).
    extra =
      [
        {:dersig, p.bip66_height},
        {:checklocktimeverify, p.bip65_height},
        {:checksequenceverify, p.csv_height},
        # BIP147 NULLDUMMY activated with segwit
        {:nulldummy, p.segwit_height}
      ]
      |> Enum.filter(fn {_f, h} -> height >= h end)
      |> Enum.map(&elem(&1, 0))

    Kernel.flags_to_int(base ++ extra)
  end
end
