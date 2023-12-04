defmodule Kevo.Api.Queries.Getlocks do
  @moduledoc false

  alias Kevo.Api.Request
  alias Kevo.ApiError, as: Err

  def request(user_id) do
    %Request{
      method: "GET",
      path: "/api/v2/users/#{user_id}/locks"
    }
  end

  def handle(request, 200, _headers, body) do
    case Jason.decode(body) do
      {:ok, %{"locks" => locks}} ->
        {:ok, locks}

      {:error, error} ->
        Err.from_body(request, error)
    end
  end

  def handle(request, status, headers, body) do
    Err.from_status(request, {status, headers, body}, 200)
  end
end
