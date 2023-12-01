defmodule Kevo do
  @moduledoc """
  Todo: Write some nice documentation here :)
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
end
