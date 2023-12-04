defmodule Kevo.Api.Request do
  @moduledoc false

  defstruct [:method, :path, headers: [], body: <<>>]
end
