defmodule GetLock do
  alias Kevo.Api.Error, as: Err

  def request(lock_id) do
    {"GET", "/api/v2/locks/#{lock_id}", [], <<>>}
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
