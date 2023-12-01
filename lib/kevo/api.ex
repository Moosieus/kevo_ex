defmodule Kevo.Api do
  @moduledoc false

  @doc false
  def get_locks() do
    GenServer.call(Kevo.Api.Client, :get_locks)
  end

  @doc false
  def get_lock(lock_id) do
    GenServer.call(Kevo.Api.Client, {:get_lock, lock_id})
  end

  @doc false
  def lock(lock_id) do
    GenServer.call(Kevo.Api.Client, {:lock, lock_id})
  end

  @doc false
  def unlock(lock_id) do
    GenServer.call(Kevo.Api.Client, {:unlock, lock_id})
  end

  @doc false
  def get_events(lock_id, page, page_size) do
    GenServer.call(Kevo.Api.Client, {:get_events, lock_id, page, page_size})
  end

  @doc false
  def ws_startup_config() do
    GenServer.call(Kevo.Api.Client, :ws_init)
  end
end
