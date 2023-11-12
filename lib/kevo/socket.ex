defmodule Kevo.Socket do
  use WebSockex

  @user_agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"

  @unikey_ws_url_base "wss://resi-prd-ws.unikey.com"

  def start_link({auth_token, server_nonce, user_id}) do
    state = %{
      auth_token: auth_token,
      server_nonce: server_nonce,
      user_id: user_id
    }

    WebSockex.start_link(
      ws_url(auth_token, server_nonce, user_id),
      __MODULE__,
      state,
      extra_headers: [{"User-Agent", @user_agent}]
    )
  end

  # need to call "/login" to get access token
  defp ws_url(auth_token, server_nonce, user_id) do
    client_nonce = client_nonce()

    query =
      URI.encode_query(%{
        "Authorization" => "Bearer #{auth_token}",
        "X-unikey-context" => "web",
        "X-unikey-cnonce" => client_nonce,
        "X-unikey-nonce" => server_nonce,
        "X-unikey-request-verification" => ws_verification(client_nonce, server_nonce),
        "X-unikey-message-content-type" => "application/json"
      })

    # may need to escape the following characters: !~*'()

    "#{Kevo.unikey_ws_url_base()}/v3/web/#{user_id}?#{query}"
  end

  # Generate the verification value used to connect to the websocket.
  defp ws_verification(client_nonce, server_nonce) do
    :crypto.mac(:hmac, :sha512, Kevo.client_secret(), client_nonce <> server_nonce)
  end

  defp client_nonce() do
    Base.encode64(:crypto.strong_rand_bytes(64))
  end
end
