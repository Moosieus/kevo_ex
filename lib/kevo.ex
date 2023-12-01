defmodule Kevo do
  @moduledoc """
  Top-level supervisor for all the processes required to communicate with Kevo.

  For API calls and websocket events, see `Kevo.Api` and `Kevo.Socket` respectively.
  """
  use Supervisor

  @spec start_link(config :: keyword()) :: Supervisor.on_start()
  def start_link(config \\ []) do
    Supervisor.start_link(__MODULE__, config)
  end

  @impl true
  def init({username, password, websocket_callback}) do
    children = [
      {Kevo.Api.Client, username: username, password: password, name: Kevo.Api.Client},
      {Kevo.Socket, name: Kevo.Socket, callback_module: websocket_callback}
    ]

    Supervisor.init(children, strategy: :one_for_all)
  end
end
