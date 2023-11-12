defmodule Kevo.Supervisor do
  use Supervisor

  @doc """

  """
  @spec start_link(config :: keyword()) :: Supervisor.on_start()
  def start_link(config) do
    Supervisor.start_link(__MODULE__, config)
  end

  @impl true
  def init(config) do

    # initialize Finch (use spec if given, otherwise default)
    # call "/login"
    # initialize the Websocket

    finch_name = KevoFinch

    children = [
      {Finch, name: finch_name},
      {Kevo, finch: finch_name}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
