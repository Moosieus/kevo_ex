defmodule Kevo.Api.Auth do
  @moduledoc """
  An auth response from logging in.
  """
  defstruct [
    :access_token,
    :id_token,
    :refresh_token,
    :expires_at,
    :user_id
  ]
end
