defmodule Kevo.Api.Request do
  @moduledoc """
  Used for logging errors.
  """
  defstruct method: "", location: "", headers: [], body: <<>>
end
