defmodule Kevo.Api do
  @moduledoc """
  User-level interface for calling Kevo from other Elixir libraries.
  """

  @doc """
  Retrieves all locks visible to the logged in user.
  """
  def get_locks() do
    GenServer.call(Kevo.Api.Statem, :get_locks)
  end

  @doc """
  Retrieves the lock's state.
  """
  def get_lock(lock_id) do
    GenServer.call(Kevo.Api.Statem, {:get_lock, lock_id})
  end

  def lock(lock_id) do
    GenServer.call(Kevo.Api.Statem, {:lock, lock_id})
  end

  @doc """
  Get events for the lock. Follows the frontend's paging behavior.
  """
  def get_events(lock_id, page \\ 1, page_size \\ 10) do
    GenServer.call(Kevo.Api.Statem, {:get_events, lock_id, page, page_size})
  end

  def unlock(lock_id) do
    GenServer.call(Kevo.Api.Statem, {:unlock, lock_id})
  end
end
