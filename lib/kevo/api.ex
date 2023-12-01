defmodule Kevo.Api do
  @moduledoc """
  User-level interface for calling Kevo from other Elixir libraries.
  """

  @doc """
  Retrieves all locks visible to the logged in user.
  """
  def get_locks() do
    GenServer.call(Kevo.Api.Client, :get_locks)
  end

  @doc """
  Retrieves the given lock's state.
  """
  def get_lock(lock_id) do
    GenServer.call(Kevo.Api.Client, {:get_lock, lock_id})
  end

  @doc """
  Locks the given lock.
  """
  @spec lock(String.t()) :: :ok | {:error, Kevo.Api.Error.t()}
  def lock(lock_id) do
    GenServer.call(Kevo.Api.Client, {:lock, lock_id})
  end

  @doc """
  Unlocks the given lock.
  """
  @spec unlock(String.t()) :: :ok | {:error, Kevo.Api.Error.t()}
  def unlock(lock_id) do
    GenServer.call(Kevo.Api.Client, {:unlock, lock_id})
  end

  @doc """
  Gets the provided lock's event history. Follows the frontend's paging behavior.
  """
  def get_events(lock_id, page \\ 1, page_size \\ 10) do
    GenServer.call(Kevo.Api.Client, {:get_events, lock_id, page, page_size})
  end

  @doc false
  def ws_startup_config() do
    GenServer.call(Kevo.Api.Client, :ws_init)
  end
end
