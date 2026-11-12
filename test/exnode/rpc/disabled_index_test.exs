defmodule Exnode.RPC.DisabledIndexTest do
  @moduledoc """
  SVC-2 (STATE_MACHINES.md): with the filter index disabled the node
  used to pass `filter_index: false` (not nil) to the methods, and
  `getblockfilter` crashed with a CaseClauseError (-32603 plus an error log)
  instead of Core's "Index is not enabled for filtertype basic".
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.Headers
  alias Exnode.Crypto.Hash
  alias Exnode.RPC.Methods
  alias Exnode.Store.KV

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)

  test "getblockfilter with the index disabled answers 'not enabled' for false and nil", %{
    tmp_dir: dir
  } do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    genesis = Hash.to_hex(@p.genesis.header.hash)

    for disabled <- [false, nil] do
      ctx = %{headers: hs, params: @p, filter_index: disabled}

      assert {:error, -1, "Index is not enabled for filtertype basic"} =
               Methods.call("getblockfilter", [genesis], ctx)
    end
  end
end
