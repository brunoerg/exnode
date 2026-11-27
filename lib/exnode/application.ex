defmodule Exnode.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Exnode.Node.Handles
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Exnode.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # SIGTERM / init:stop: the nodes under this supervisor are stopping, not
  # restarting (Exnode.Node.stopping?/1).
  @impl true
  def prep_stop(state) do
    Exnode.Node.mark_stopping(:all)
    state
  end
end
