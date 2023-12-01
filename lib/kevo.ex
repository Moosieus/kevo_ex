defmodule Kevo do
  @moduledoc """
  Todo: Write some nice documentation here :)
  """
  use Supervisor

  # crib the naming scheme from Finch - they do it right.
  # Module.start_link parses the keyword list for the config map
  # config map's passed to `Supervisor.start_link`
  # name's passed as an OTP option

  @spec start_link(opts :: keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    name = kevo_name!(opts)

    config = %{
      name: name,
      api_name: api_name(name),
      socket_name: socket_name(name),
      username: username!(opts),
      password: password!(opts),
      ws_callback_module: ws_callback_module(opts)
    }

    Supervisor.start_link(__MODULE__, config, name: name)
  end

  @impl true
  def init(config) do
    api =
      {Kevo.Api.Client,
       [username: config.username, password: config.password, name: config.api_name]}

    socket =
      case config.ws_callback_module do
        nil -> []
        module -> [{Kevo.Socket, [callback_module: module, name: config.socket_name]}]
      end

    Supervisor.init([api | socket], strategy: :one_for_one)
  end

  @doc """
  Retrieves all locks visible to the logged in user.
  """
  defdelegate get_locks(), to: Kevo.Api

  @doc """
  Retrieves the given lock's state.
  """
  @spec get_lock(String.t()) :: {:ok, any()} | {:error, Kevo.Api.Error.t()}
  defdelegate get_lock(lock_id), to: Kevo.Api

  @doc """
  Locks the given lock.
  """
  @spec lock(String.t()) :: :ok | {:error, Kevo.Api.Error.t()}
  defdelegate lock(lock_id), to: Kevo.Api

  @doc """
  Unlocks the given lock.
  """
  @spec unlock(String.t()) :: :ok | {:error, Kevo.Api.Error.t()}
  defdelegate unlock(lock_id), to: Kevo.Api

  @doc """
  Gets the provided lock's event history. Follows the frontend's paging behavior.
  """
  defdelegate get_events(lock_id, page \\ 1, page_size \\ 10), to: Kevo.Api

  ## Configuration

  def child_spec(opts) do
    %{
      id: kevo_name!(opts),
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  defp kevo_name!(opts) do
    Keyword.get(opts, :name) || raise(ArgumentError, "must supply a name")
  end

  defp api_name(name), do: :"#{name}.Api.Client"
  defp socket_name(name), do: :"#{name}.Socket"

  defp username!(opts) do
    Keyword.get(opts, :username) || raise(ArgumentError, "must supply a username")
  end

  defp password!(opts) do
    Keyword.get(opts, :password) || raise(ArgumentError, "must supply a password")
  end

  defp ws_callback_module(opts) do
    Keyword.get(opts, :ws_callback_module)
  end
end
