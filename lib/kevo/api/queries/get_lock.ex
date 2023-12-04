defmodule Kevo.Api.Queries.Getlock do
  @moduledoc false

  alias Kevo.Api.Request
  alias Kevo.ApiError, as: Err

  def request(lock_id) do
    %Request{
      method: "GET",
      path: "/api/v2/locks/#{lock_id}"
    }
  end

  def handle(request, 200, _headers, body) do
    case Jason.decode(body) do
      {:ok, lock} ->
        {:ok, lock}

      {:error, error} ->
        Err.from_body(request, error)
    end
  end

  def handle(request, status, headers, body) do
    Err.from_status(request, {status, headers, body}, 200)
  end
end
