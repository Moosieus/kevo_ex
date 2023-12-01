defmodule TestCallback do
  # use Kevo.Handler

  require Logger

  # @impl true
  def handle_event(json) do
    Logger.info("GOT THE JSON :D")
    Logger.info(json)
  end
end
