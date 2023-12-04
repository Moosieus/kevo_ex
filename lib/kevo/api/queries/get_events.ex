defmodule Kevo.Api.Queries.Getevents do
  @moduledoc false

  alias Kevo.Api.Request
  alias Kevo.ApiError, as: Err

  def request(lock_id, page, page_size) do
    %Request{
      method: "GET",
      path: "/api/v2/locks/#{lock_id}/events?page=#{page}&pageSize=#{page_size}"
    }
  end

  def handle(request, 200, _headers, body) do
    case Jason.decode(body) do
      {:ok, events} ->
        {:ok, events}

      {:error, error} ->
        Err.from_body(request, error)
    end
  end

  def handle(request, status, headers, body) do
    Err.from_status(request, {status, headers, body}, 200)
  end
end
