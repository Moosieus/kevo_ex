defmodule Kevo.Api do
  @moduledoc false

  @doc false
  def get_locks(name) do
    GenServer.call(:"#{name}.Api.Client", :get_locks)
  end

  @doc false
  def get_lock(lock_id, name) do
    GenServer.call(:"#{name}.Api.Client", {:get_lock, lock_id})
  end

  @doc false
  def lock(lock_id, name) do
    GenServer.call(:"#{name}.Api.Client", {:lock, lock_id})
  end

  @doc false
  def unlock(lock_id, name) do
    GenServer.call(:"#{name}.Api.Client", {:unlock, lock_id})
  end

  @doc false
  def get_events(lock_id, page, page_size, name) do
    GenServer.call(:"#{name}.Api.Client", {:get_events, lock_id, page, page_size})
  end

  @doc false
  def ws_startup_config(api_name) do
    GenServer.call(api_name, :ws_init)
  end
end
