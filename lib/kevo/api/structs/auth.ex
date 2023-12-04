defmodule Kevo.Api.Auth do
  @moduledoc false

  defstruct [
    :access_token,
    :id_token,
    :refresh_token,
    :expires_at,
    :user_id
  ]
end
