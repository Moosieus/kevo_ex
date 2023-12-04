defmodule Kevo.Api.Queries.Sendcommand do
  @moduledoc false

  alias Kevo.Api.Request
  alias Kevo.ApiError, as: Err

  # specifies request data
  def request(user_id, lock_id, command) do
    body = Jason.encode!(%{"command" => command})

    %Request{
      method: "POST",
      path: "/api/v2/users/#{user_id}/locks/#{lock_id}/commands",
      headers: [
        {"Content-Type", "application/json"},
        {"Content-Length", "#{byte_size(body)}"}
      ],
      body: body
    }
  end

  def handle(_request, 201, _headers, _body) do
    :ok
  end

  def handle(request, status, headers, body) do
    Err.from_status(request, {status, headers, body}, 201)
  end
end
