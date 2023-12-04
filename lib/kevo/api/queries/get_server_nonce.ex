defmodule GetServerNonce do
  alias Kevo.Api.Error, as: Err

  def request() do
    {
      "POST",
      "/api/v2/nonces",
      [{"Content-Type", "application/json"}],
      ~s({"headers":{"Accept": "application/json"}})
    }
  end

  def handle(request, 201, headers, body) do
    case List.keyfind(headers, "x-unikey-nonce", 0) do
      {"x-unikey-nonce", server_nonce} ->
        {:ok, server_nonce}

      nil ->
        Err.from_headers(request, {201, headers, body}, 201)
    end
  end

  def handle(request, status, headers, body) do
    Err.from_status(request, {status, headers, body}, 201)
  end
end
