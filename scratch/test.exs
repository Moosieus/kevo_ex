defmodule TestCallback do
  # use Kevo.Handler

  require Logger

  # @impl true
  def handle_event(json) do
    Logger.info("GOT THE JSON :D")
    IO.inspect(json, label: "websocket message, Jason decoded.")
  end
end

Logger.configure(level: :debug)
Logger.add_translator({Kevo.StateMachineTranslator, :translate})

Kevo.start_link([
  name: Kevo,
  username: System.get_env("KEVO_USER"),
  password: System.get_env("KEVO_PASSWORD"),
  ws_callback_module: TestCallback
])
