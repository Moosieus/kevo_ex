defmodule Kevo do
  @moduledoc """
  Top-level interface and supervisor for Kevo's API and websocket connections.
  """

  use Supervisor

  require Logger

  ## Initialization

  def child_spec(opts) do
    %{
      id: name(opts),
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  @doc """
  Starts an instance of kevo_ex.

  ## Configuration
  * `:name` - Alias of the top-level supervisor. Can be provided if you intend to run multiple instances of `kevo_ex` in your app. Defaults to `Kevo`.

  * `:username` - Your Kevo username (required).

  * `:password` - Your Kevo password (required).

  * `:ws_callback_module` - Websocket callback module. Defaults to `nil`.
  """
  @spec start_link(opts :: keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Logger.add_translator({Kevo.StateMachineTranslator, :translate})

    name = name(opts)

    config = %{
      username: username!(opts),
      password: password!(opts),
      api_name: api_name(name),
      socket_name: socket_name(name),
      ws_callback_module: ws_callback_module(opts)
    }

    Supervisor.start_link(__MODULE__, config, name: name)
  end

  @impl true
  def init(config) do
    %{
      username: username,
      password: password,
      api_name: api_name,
      socket_name: socket_name,
      ws_callback_module: ws_callback_module
    } = config

    api =
      {Kevo.Api.Client, [username: username, password: password, name: api_name]}

    socket =
      case ws_callback_module do
        nil ->
          []

        module ->
          [{Kevo.Socket, [callback_module: module, name: socket_name, api_name: api_name]}]
      end

    Supervisor.init([api | socket], strategy: :one_for_one)
  end

  defp name(opts) do
    Keyword.get(opts, :name, Kevo)
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

  ## Developer API

  @doc """
  Retrieves all locks visible to the logged in user.
  """
  @spec get_locks(atom()) :: {:ok, list(map())} | {:error, Kevo.ApiError.t()}
  defdelegate get_locks(name \\ Kevo), to: Kevo.Api

  @doc """
  Retrieves the given lock's state.
  """
  @spec get_lock(String.t(), atom()) ::
          {:ok, map()} | {:error, Kevo.ApiError.t()}
  defdelegate get_lock(lock_id, name \\ Kevo), to: Kevo.Api

  @doc """
  Locks the given lock.
  """
  @spec lock(String.t(), atom()) :: :ok | {:error, Kevo.ApiError.t()}
  defdelegate lock(lock_id, name \\ Kevo), to: Kevo.Api

  @doc """
  Unlocks the given lock.
  """
  @spec unlock(String.t(), atom()) :: :ok | {:error, Kevo.ApiError.t()}
  defdelegate unlock(lock_id, name \\ Kevo), to: Kevo.Api

  @doc """
  Gets the provided lock's event history. Follows the frontend's paging behavior.
  """
  @spec get_events(String.t(), integer(), integer(), atom()) ::
          {:ok, list(map())} | {:error, Kevo.ApiError.t()}
  defdelegate get_events(lock_id, page \\ 1, page_size \\ 10, name \\ Kevo), to: Kevo.Api
end
