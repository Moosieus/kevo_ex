defmodule Kevo.Socket do
  @moduledoc """
  A websocket client for receiving events from Kevo.

  The relationship's receive-only, Kevo doesn't take any messages from the client.
  """

  @behaviour :gen_statem

  require Logger

  import Kevo.Common

  @user_agent {"User-Agent",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"}

  @impl true
  def callback_mode, do: :state_functions

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 500
    }
  end

  @spec start_link(opts :: keyword()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_link(opts) do
    config = %{
      ws_cb: websocket_callback!(opts)
    }

    :gen_statem.start_link({:global, __MODULE__}, __MODULE__, config, opts)
  end

  @impl true
  def init(config) do
    {:ok, :initializing, config, {:next_event, :internal, :initialize}}
  end

  def initializing(:internal, :initialize, %{ws_cb: ws_cb} = _data) do
    Logger.debug("opening websocket", state: :initializing)

    {:ok, {access_token, user_id, snonce}} = Kevo.Api.ws_startup_config()

    {:ok, conn} = :gun.open(~c"#{unikey_ws_url_base()}", 443, gun_ws_opts())
    {:ok, :http} = :gun.await_up(conn, 5_000)

    stream = :gun.ws_upgrade(conn, ws_location(access_token, snonce, user_id), [@user_agent])
    {:upgrade, ["websocket"], _} = :gun.await(conn, stream, 5_000)

    data = %{
      conn: conn,
      stream: stream,
      ws_cb: ws_cb
    }

    Logger.debug("websocket connection established.", state: :initializing)

    {:next_state, :connected, data}
  end

  def connected(:info, {:gun_ws, _worker, _stream, {:text, frame}}, %{ws_cb: websocket_callback} =  _data) do
    Logger.debug("got websocket message", state: :connected)

    Logger.info([msg: "websocket message", json: Jason.decode!(frame)])
    # |> websocket_callback.()

    :keep_state_and_data
  end

  # websocket closed

  def connected(:info, {:gun_ws, conn, stream, :close}, %{conn: conn, stream: stream} = _data) do
    Logger.debug("websocket closed (unknown reason)", state: :connected)

    {
      :keep_state_and_data,
      {:next_event, :internal, :reconnect}
    }
  end

  def connected(:info, {:gun_ws, conn, _stream, {:close, errno, reason}}, %{conn: conn} = _data) do
    Logger.debug("websocket closed (errno #{errno}, reason #{inspect(reason)})",
      state: :connected
    )

    {
      :keep_state_and_data,
      {:next_event, :internal, :reconnect}
    }
  end

  def connected(:info, {:gun_down, conn, _proto, _reason, _killed_streams}, %{conn: conn} = _data) do
    Logger.debug("Lost complete shard connection. Attempting reconnect.", state: :connected)

    {
      :keep_state_and_data,
      {:next_event, :internal, :reconnect}
    }
  end

  # Internal event to force a complete reconnection from the connected state.
  # Useful when the gateway told us to do so.
  def connected(:internal, :reconnect, %{conn: conn} = data) do
    Logger.debug("reconnecting", state: :connected)

    :ok = :gun.close(conn)
    :ok = :gun.flush(conn)

    {
      :next_state,
      :initializing,
      %{data | conn: nil, stream: nil},
      {:next_event, :internal, :initialize}
    }
  end

  # need to call "/login" to get access token
  defp ws_location(access_token, server_nonce, user_id) do
    client_nonce = client_nonce()

    query =
      URI.encode_query(%{
        "Authorization" => "Bearer #{access_token}",
        "X-unikey-context" => "web",
        "X-unikey-cnonce" => client_nonce,
        "X-unikey-nonce" => server_nonce,
        "X-unikey-request-verification" => ws_verification(client_nonce, server_nonce),
        "X-unikey-message-content-type" => "application/json"
      })

    # may need to escape the following characters: !~*'()

    "/v3/web/#{user_id}?#{query}"
  end

  # Generate the verification value used to connect to the websocket.
  defp ws_verification(client_nonce, server_nonce) do
    :crypto.mac(:hmac, :sha512, client_secret(), client_nonce <> server_nonce)
  end

  ## Configuration options

  defp websocket_callback!(opts) do
    Keyword.get(opts, :ws_cb) || raise(ArgumentError, "must supply a websocket callback")
  end
end
