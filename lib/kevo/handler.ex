defmodule Kevo.Handler do
  @moduledoc """
  Handler behaviour for events received from Kevo's websocket.
  """

  @callback handle_event(event :: map()) :: any
end
