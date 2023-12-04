defmodule Kevo.Api.Refresh do
  @moduledoc false

  # A refresh token response.

  defstruct [
    :access_token,
    :id_token,
    :refresh_token,
    :expires_at
  ]
end
