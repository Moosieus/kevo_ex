defmodule Kevo.Api.Queries.Sendcommand do
  alias Kevo.Api.Error, as: Err

  # specifies request data
  def request(user_id, lock_id, command) do
    location = "/api/v2/users/#{user_id}/locks/#{lock_id}/commands"

    body = Jason.encode!(%{"command" => command})

    headers = [
      {"Content-Type", "application/json"},
      {"Content-Length", "#{byte_size(body)}"}
    ]

    {"POST", location, headers, body}
  end

  def handle(_request, 201, _headers, _body) do
    :ok
  end

  def handle(request, status, headers, body) do
    Err.from_status(request, {status, headers, body}, 201)
  end
end
