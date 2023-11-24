defmodule Kevo.Supervisor do
  @moduledoc """
  Root supervisor for all the processes required to communicate with Kevo.
  """
  use Supervisor

  @spec start_link(config :: keyword()) :: Supervisor.on_start()
  def start_link(config) do
    Supervisor.start_link(__MODULE__, config)
  end

  @impl true
  def init(_config) do
    gun_login_client = %{
      id: Kevo.Gun.Login,
      start: {:gun, :start_link, [self(), ~c"identity.unikey.com", 443, %{transport: :tls}]}
    }

    gun_api_client = %{
      id: Kevo.Gun.API,
      start: {:gun, :start_link, [self(), ~c"resi-prd-api.unikey.com", 443, %{transport: :tls}]}
    }

    children = [
      gun_login_client,
      gun_api_client
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
