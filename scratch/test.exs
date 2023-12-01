defmodule TestCallback do
  # use Kevo.Handler

  require Logger

  # @impl true
  def handle_event(json) do
    Logger.info("GOT THE JSON :D")
    Logger.info(json)
  end
end


Logger.configure(level: :debug)
Logger.add_translator({Kevo.StateMachineTranslator, :translate})

Kevo.Supervisor.start_link({
  System.get_env("KEVO_USER"),
  System.get_env("KEVO_PASSWORD"),
  TestCallback}
)
