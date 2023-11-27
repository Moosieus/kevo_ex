defmodule Kevo.Supervisor do
  @moduledoc """
  Root supervisor for all the processes required to communicate with Kevo.
  """
  use Supervisor

  @spec start_link(config :: keyword()) :: Supervisor.on_start()
  def start_link(config \\ []) do
    Supervisor.start_link(__MODULE__, config)
  end

  @impl true
  def init(_config) do
    children = []
    Supervisor.init(children, strategy: :one_for_one)
  end
end
