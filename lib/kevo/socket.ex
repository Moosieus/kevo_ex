defmodule Kevo.Socket do
  @moduledoc false

  # A websocket client for receiving events from Kevo.
  # The relationship's receive-only, Kevo doesn't take any messages from the client.

  @behaviour :gen_statem

  require Logger

  import Kevo.Common

  @user_agent {"User-Agent",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"}

  @impl true
  def callback_mode, do: :state_functions

  @spec start_link(opts :: keyword()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_link(opts) do
    config = %{
      callback_module: callback_module!(opts)
    }

    :gen_statem.start_link({:global, __MODULE__}, __MODULE__, config, opts)
  end

  @impl true
  def init(config) do
    {:ok, :initializing, config, {:next_event, :internal, :initialize}}
  end

  ## State Machine

  def initializing(:internal, :initialize, %{callback_module: callback_module} = _data) do
    Logger.debug("opening Kevo websocket...", state: :initializing)

    {:ok, {access_token, user_id, snonce}} = Kevo.Api.ws_startup_config()

    {:ok, conn} = :gun.open(~c"#{unikey_ws_url_base()}", 443, gun_ws_opts())
    {:ok, :http} = :gun.await_up(conn, 5_000)

    stream = :gun.ws_upgrade(conn, ws_location(access_token, snonce, user_id), [@user_agent])
    {:upgrade, ["websocket"], _} = :gun.await(conn, stream, 5_000)

    Logger.debug("Kevo websocket connection established", state: :initializing)

    data = %{
      conn: conn,
      stream: stream,
      callback_module: callback_module
    }

    {:next_state, :connected, data}
  end

  def connected(
        :info,
        {:gun_ws, _worker, _stream, {:text, frame}},
        %{callback_module: callback_module} = _data
      ) do
    Logger.debug("Kevo websocket got frame", state: :connected)

    Jason.decode!(frame)
    |> callback_module.handle_event()

    :keep_state_and_data
  end

  # websocket closed

  def connected(:info, {:gun_ws, conn, stream, :close}, %{conn: conn, stream: stream} = _data) do
    Logger.debug("Kevo websocket closed (normal/close frame)", state: :connected)

    {
      :keep_state_and_data,
      {:next_event, :internal, :reconnect}
    }
  end

  def connected(:info, {:gun_ws, conn, _stream, {:close, errno, reason}}, %{conn: conn} = _data) do
    Logger.debug("Kevo websocket closed (errno #{errno}): #{inspect(reason)}",
      state: :connected,
      reason: reason
    )

    {
      :keep_state_and_data,
      {:next_event, :internal, :reconnect}
    }
  end

  def connected(:info, {:gun_down, conn, _proto, reason, _dead_streams}, %{conn: conn} = _data) do
    Logger.debug("underlying Kevo websocket connection died: #{inspect(reason)}",
      state: :connected,
      reason: reason
    )

    {
      :keep_state_and_data,
      {:next_event, :internal, :reconnect}
    }
  end

  # called after connection's lost for any of the above reasons
  def connected(:internal, :reconnect, %{conn: conn} = data) do
    Logger.debug("Kevo websocket reconnecting...", state: :connected)

    :ok = :gun.close(conn)
    :ok = :gun.flush(conn)

    {
      :next_state,
      :initializing,
      %{data | conn: nil, stream: nil},
      {:next_event, :internal, :initialize}
    }
  end

  # websocket connection endpoint
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

  ## Configuration

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 500
    }
  end

  defp callback_module!(opts) do
    Keyword.get(opts, :callback_module) ||
      raise(ArgumentError, "must supply a websocket callback")
  end
end
