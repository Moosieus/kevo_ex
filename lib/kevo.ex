defmodule Kevo do
  def get_locks(timeout \\ 5000) do
    GenServer.call(Kevo.Api, :get_locks, timeout)
  end
end
