defmodule Exnode.RPC.ServerTest do
  use ExUnit.Case, async: true
  import Plug.Test
  alias Exnode.RPC.Server

  defp request(batch) do
    conn(:post, "/", Jason.encode!(batch))
    |> Plug.Conn.put_req_header("authorization", "Basic " <> Base.encode64("u:p"))
    |> Server.call(%{auth: [{"u", "p"}], ctx: %{}})
  end

  test "oversize batches are rejected before executing any method" do
    # No context exists to execute getblockcount. A rejected batch must not
    # attempt it, even for the first element.
    req = %{jsonrpc: "2.0", id: 7, method: "getblockcount", params: []}
    c = request(List.duplicate(req, Server.max_batch_size() + 1))
    assert c.status == 400
    assert %{"id" => nil, "error" => %{"code" => -32600}} = Jason.decode!(c.resp_body)
  end

  test "the batch boundary is inclusive and replies retain request order" do
    reqs =
      for id <- 1..Server.max_batch_size(),
          do: %{jsonrpc: "2.0", id: id, method: "no-such-method"}

    c = request(reqs)
    assert c.status == 200
    replies = Jason.decode!(c.resp_body)
    assert Enum.map(replies, & &1["id"]) == Enum.to_list(1..Server.max_batch_size())
    assert Enum.all?(replies, &(&1["error"]["code"] == -32601))
    assert Jason.decode!(request([]).resp_body) == []
  end
end
