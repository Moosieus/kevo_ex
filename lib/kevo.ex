defmodule Kevo do
  def get_locks(timeout \\ 5000) do
    GenServer.call(Kevo.API, :get_locks, timeout)
  end
end
