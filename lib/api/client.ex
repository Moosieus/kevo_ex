defmodule Kevo.Api.Client do
  @moduledoc """
  A state machine that handles the authentication and connection to Kevo's HTTP API.

  HTTP requests sent by this client are blocking for now.
  This could be revisited one day, but for now I don't want perfect to be the enemy of good.
  """
  @behaviour :gen_statem

  require Logger

  import Kevo.Common

  alias Kevo.Api.{
    Auth,
    Refresh,
    Request,
    Error
  }

  defmodule Data do
    defstruct [
      :username,
      :password,
      :access_token,
      :id_token,
      :refresh_token,
      :expires_at,
      :user_id,
      :api_conn
    ]
  end

  @impl true
  def callback_mode, do: :state_functions

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :transient,
      shutdown: 500
    }
  end

  @spec start_link(opts :: keyword()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_link(opts) do
    config = %{
      username: username!(opts),
      password: password!(opts)
    }

    :gen_statem.start_link({:local, __MODULE__}, __MODULE__, config, opts)
  end

  @impl true
  def init(data) do
    {:ok, :initializing, data, [{:next_event, :internal, :initialize}]}
  end

  defp login(username, password) do
    {code_verifier, code_challenge} = Kevo.Pkce.generate_pkce_pair()
    device_id = UUID.uuid4()
    auth_url = auth_url(code_challenge, device_id)

    with {:ok, conn} <- :gun.open(~c"#{unikey_login_url_base()}", 443, gun_opts()),
         {:ok, _} <- :gun.await_up(conn),
         {:ok, login_page_url} <- get_login_url(conn, auth_url),
         {:ok, login_form, cookies} <- get_login_page(conn, login_page_url),
         {verification_token, serialized_client} <- scrape_login_form(login_form),
         {:ok, unikey_redirect_location, cookies} <-
           submit_login(
             conn,
             username,
             password,
             cookies,
             serialized_client,
             verification_token
           ),
         {:ok, code} <- get_unikey_code(conn, unikey_redirect_location, cookies),
         {:ok, auth} <- post_jwt(conn, code, code_verifier, cookies),
         :ok <- :gun.close(conn) do
      {:ok, auth}
    else
      {:error, error} ->
        {:error, error}
    end
  end

  # Login sub-functions

  defp auth_url(code_challenge, device_uuid4) do
    certificate = generate_certificate(device_uuid4)
    client_id = client_id()
    state = :crypto.hash(:md5, :crypto.strong_rand_bytes(32))

    "/connect/authorize?" <>
      URI.encode_query(
        %{
          "client_id" => client_id,
          "redirect_uri" => "https://mykevo.com/#/token",
          "response_type" => "code",
          "scope" => "openid email profile identity.api tumbler.api tumbler.ws offline_access",
          "state" => state,
          "code_challenge" => code_challenge,
          "code_challenge_method" => "S256",
          "prompt" => "login",
          "response_mode" => "query",
          "acr_values" =>
            "\n    appId:#{client_id}\n    tenant:#{tenant_id()}\n    tenantCode:KWK\n    tenantClientId:#{client_id}\n    loginContext:Web\n    deviceType:Browser\n    deviceName:Chrome,(Windows)\n    deviceMake:Chrome,108.0.0.0\n    deviceModel:Windows,10\n    deviceVersion:rp-1.0.2\n    staticDeviceId:#{device_uuid4}\n    deviceCertificate:#{certificate}\n    isDark:false"
        },
        :rfc3986
      )
  end

  defp get_login_url(conn, auth_url) do
    request = %Request{method: "GET", location: auth_url}
    stream_ref = :gun.get(conn, ~c"#{auth_url}")

    case :gun.await(conn, stream_ref) do
      {:response, :fin, 302, headers} ->
        {"location", "https://identity.unikey.com" <> redirect_location} =
          List.keyfind!(headers, "location", 0)

        {:ok, redirect_location}

      {:response, _, status, headers} ->
        Error.from_status(request, {status, headers}, 302, __ENV__.function)

      {:error, error} ->
        Error.from_network(request, error, __ENV__.function)
    end
  end

  defp get_login_page(conn, login_page_url) do
    request = %Request{method: "GET", location: login_page_url}
    stream_ref = :gun.get(conn, login_page_url)

    case :gun.await(conn, stream_ref) do
      {:response, :nofin, 200, headers} ->
        {:ok, login_form} = :gun.await_body(conn, stream_ref)
        {:ok, login_form, get_cookies(headers)}

      {:response, _, _, _} = response ->
        Error.from_status(request, response, 200, __ENV__.function)

      {:error, error} ->
        Error.from_network(request, error, __ENV__.function)
    end
  end

  # need to check if the form is matched correctly.
  defp scrape_login_form(html) do
    %{"token" => request_verification_token} =
      Regex.named_captures(
        ~r/<input.* name="__RequestVerificationToken".* value="(?<token>.*)"/,
        html
      )

    %{"token" => serialized_client} =
      Regex.named_captures(~r/<input.* name="SerializedClient".* value="(?<token>.*)"/, html)

    {request_verification_token, HtmlEntities.decode(serialized_client)}
  end

  defp submit_login(conn, username, password, cookies, serialized_client, verification_token) do
    location = "/account/login"

    req_headers = [
      {"Cookie", Enum.join(cookies, "; ")},
      {"host", "identity.unikey.com"},
      {"accept", "*/*"},
      {"content-type", "application/x-www-form-urlencoded"}
    ]

    body =
      www_form_encode(%{
        "SerializedClient" => serialized_client,
        "NumFailedAttempts" => "0",
        "Username" => username,
        "Password" => password,
        "login" => "",
        "__RequestVerificationToken" => verification_token
      })

    request = %Request{
      method: "POST",
      location: location,
      headers: req_headers,
      body: body
    }

    stream_ref = :gun.post(conn, location, req_headers, body)

    case :gun.await(conn, stream_ref) do
      {:response, :fin, 302, res_headers} ->
        {"set-cookie", cookie} = List.keyfind!(res_headers, "set-cookie", 0)
        {"location", location} = List.keyfind!(res_headers, "location", 0)
        {:ok, location, [cookie | cookies]}

      {:response, _, _, _} = response ->
        Error.from_status(request, response, 302, __ENV__.function)

      {:error, error} ->
        Error.from_network(request, error, __ENV__.function)
    end
  end

  defp get_unikey_code(conn, location, cookies) do
    req_headers = [{"Cookie", Enum.join(cookies, "; ")}]
    request = %Request{method: "GET", location: location, headers: req_headers}
    stream_ref = :gun.get(conn, location, req_headers)

    case :gun.await(conn, stream_ref) do
      {:response, :fin, 302, headers} ->
        {"location", redirect_location} = List.keyfind!(headers, "location", 0)
        %URI{fragment: fragment} = URI.parse(redirect_location)
        %URI{query: query} = URI.parse(fragment)
        %{"code" => code} = URI.decode_query(query)
        {:ok, code}

      {:response, _, _, _} = response ->
        Error.from_status(request, response, 302, __ENV__.function)

      {:error, error} ->
        Error.from_network(request, error, __ENV__.function)
    end
  end

  defp post_jwt(conn, code, code_verifier, cookies) do
    req_headers = [
      {"Cookie", Enum.join(cookies, "; ")},
      {"host", "identity.unikey.com"},
      {"accept", "*/*"},
      {"content-type", "application/x-www-form-urlencoded"}
    ]

    req_body =
      www_form_encode(%{
        "client_id" => client_id(),
        "client_secret" => client_secret(),
        "code" => code,
        "code_verifier" => code_verifier,
        "grant_type" => "authorization_code",
        "redirect_uri" => "https://mykevo.com/#/token"
      })

    request = %Request{
      method: "POST",
      location: "/connect/token",
      headers: req_headers,
      body: req_body
    }

    stream_ref = :gun.post(conn, "/connect/token", req_headers, req_body)

    case :gun.await(conn, stream_ref) do
      {:response, :nofin, 200, _} ->
        {:ok, body} = :gun.await_body(conn, stream_ref)
        {:ok, json} = Jason.decode(body)
        {:ok, %{"sub" => user_id}} = Joken.peek_claims(json["id_token"])

        {:ok,
         %Auth{
           :access_token => json["access_token"],
           :id_token => json["id_token"],
           :refresh_token => json["refresh_token"],
           :expires_at => expiration_timestamp(json["expires_in"]),
           :user_id => user_id
         }}

      {:response, _, _, _} = response ->
        Error.from_status(request, response, 200, __ENV__.function)

      {:error, error} ->
        Error.from_network(request, error, __ENV__.function)
    end
  end

  ## State Machine

  def initializing(:internal, :initialize, %{username: username, password: password}) do
    Logger.debug("performing login", state: :initializing)

    with {:ok, %Auth{} = auth} <- login(username, password) do
      {:next_state, :disconnected,
       %Data{
         :username => username,
         :password => password,
         :access_token => auth.access_token,
         :id_token => auth.id_token,
         :refresh_token => auth.refresh_token,
         :expires_at => auth.expires_at,
         :user_id => auth.user_id
       }}
    else
      err ->
        {:stop, :login_failed, err}
    end
  end

  # wake from rest
  def disconnected({:call, _from}, _request, %Data{} = data) do
    Logger.debug("got query, opening connection", state: :disconnected)

    {:next_state, :connecting, data,
     [
       {:next_event, :internal, :open},
       {:state_timeout, :timer.seconds(10), :connect_timeout},
       :postpone
     ]}
  end

  # startup from rest
  def connecting(:internal, :open, %Data{} = data) do
    Logger.debug("opening Kevo API connection", state: :connecting)

    {:ok, api_conn} = :gun.open(~c"#{unikey_api_url_base()}", 443, gun_opts())

    {:keep_state, %Data{data | api_conn: api_conn}}
  end

  # connection established -> connected
  def connecting(:info, {:gun_up, conn_pid, _}, %{api_conn: conn_pid} = data) do
    Logger.debug("gun established connection", state: :connecting)

    {:next_state, :connected, data}
  end

  # postpone calls while connecting
  def connecting({:call, from}, request, _data) do
    Logger.debug("postpone #{inspect(request)} call from #{inspect(from)} while connecting",
      state: :connecting
    )

    {:keep_state_and_data, :postpone}
  end

  # connecting timeout
  def connecting(:state_timeout, :connect_timeout, _data) do
    Logger.debug("state transition", state: :connected)

    {:stop, :connect_timeout}
  end

  # special case when websocket has to start
  def connected({:call, from}, :ws_init, %Data{} = data) do
    Logger.debug("retreiving websocket init data", state: :connected)

    %Data{
      access_token: access_token,
      user_id: user_id
    } = data

    reply =
      case get_server_nonce(data.api_conn) do
        {:ok, snonce} ->
          {:ok, {access_token, user_id, snonce}}

        {:error, error} ->
          {:error, error}
      end

    {:keep_state, data, [{:reply, from, reply}]}
  end

  # open for business
  def connected({:call, from}, call, %Data{} = data) do
    Logger.debug("processing call: #{call}", state: :connected)

    %{
      access_token: access_token,
      api_conn: api_conn
    } = data

    with {:ok, data} <- check_refresh(data),
         {:ok, snonce} <- get_server_nonce(api_conn) do
      resp = dispatch(call, headers(access_token, snonce), data)
      {:keep_state, data, [{:reply, from, resp}]}
    else
      err ->
        {:keep_state, data, [{:reply, from, err}]}
    end
  end

  # connection dropped
  def connected(:info, {:gun_down, conn, _, reason, _}, %Data{} = data) do
    Logger.debug("Kevo API connection closed: #{inspect(reason)}", state: :connected)

    # stop gun from reopening connection
    :ok = :gun.close(conn)
    :ok = :gun.flush(conn)

    {:next_state, :disconnected, %{data | api_conn: nil}}
  end

  def connected(:info, {:gun_data, _conn, _stream, _fin, _body}, _data) do
    Logger.debug("gun_data but we await, so just eat the message.", state: :connected)

    # I'll have to refactor this to work concurrently later, given gun's gonna do this anyway.

    :keep_state_and_data
  end

  ## REST API Calls

  defp dispatch(:get_locks, req_headers, %Data{} = data),
    do: do_get_locks(data.api_conn, req_headers, data.user_id)

  defp dispatch({:get_lock, lock_id}, req_headers, %Data{} = data),
    do: do_get_lock(data.api_conn, req_headers, lock_id)

  defp dispatch({:get_events, lock_id, page, page_size}, req_headers, %Data{} = data),
    do: do_get_events(data.api_conn, req_headers, lock_id, page, page_size)

  defp dispatch({:lock, lock_id}, req_headers, %Data{} = data),
    do: send_command(data.api_conn, req_headers, data.user_id, lock_id, lock_state_lock())

  defp dispatch({:unlock, lock_id}, req_headers, %Data{} = data),
    do: send_command(data.api_conn, req_headers, data.user_id, lock_id, lock_state_unlock())

  defp do_get_lock(conn, req_headers, lock_id) do
    location = "/api/v2/locks/#{lock_id}"
    request = %Request{method: "GET", location: location, headers: req_headers}
    stream_ref = :gun.get(conn, location, req_headers)

    with {:response, :nofin, 200, _headers} <- :gun.await(conn, stream_ref),
         {:ok, body} <- :gun.await_body(conn, stream_ref),
         {:ok, lock} <- Jason.decode(body) do
      {:ok, lock}
    else
      {:response, _, _, _} = response ->
        Error.from_status(request, response, 200)

      {:error, %Jason.DecodeError{} = error} ->
        Error.from_body(request, error)

      {:error, error} ->
        Error.from_network(request, error)
    end
  end

  defp do_get_locks(conn, req_headers, user_id) do
    alias Kevo.Api.Error, as: Err

    location = "/api/v2/users/#{user_id}/locks"
    request = %Request{method: "GET", location: location, headers: req_headers}
    stream_ref = :gun.get(conn, location, req_headers)

    with {:response, :nofin, 200, _} <- :gun.await(conn, stream_ref),
         {:ok, body} <- :gun.await_body(conn, stream_ref) do
      case Jason.decode(body) do
        {:ok, %{"locks" => locks}} ->
          {:ok, locks}

        {:error, error} ->
          {:error, Err.from_body(request, error)}
      end
    else
      {:response, :nofin, status, res_headers} ->
        {:error, Err.from_status(request, {status, res_headers}, 200)}

      {:error, error} ->
        {:error, Err.from_network(request, error)}
    end
  end

  defp do_get_events(conn, req_headers, lock_id, page, page_size) do
    alias Kevo.Api.Error, as: Err

    location = "/api/v2/locks/#{lock_id}/events?page=#{page}&pageSize=#{page_size}"
    request = %Request{method: "GET", location: location, headers: req_headers}
    stream_ref = :gun.get(conn, location, req_headers)

    with {:response, :nofin, 200, _} <- :gun.await(conn, stream_ref),
         {:ok, body} = :gun.await_body(conn, stream_ref),
         {:ok, events} <- Jason.decode(body) do
      {:ok, events}
    else
      {:response, _, status, headers} ->
        {:error, Err.from_status(request, {status, headers}, 200)}

      {:error, %Jason.DecodeError{} = err} ->
        {:error, Err.from_body(request, err)}

      {:error, error} ->
        {:error, Err.from_network(request, error)}
    end
  end

  defp send_command(conn, req_headers, user_id, lock_id, command) do
    alias Kevo.Api.Error, as: Err

    location = "/api/v2/users/#{user_id}/locks/#{lock_id}/commands"
    req_body = Jason.encode!(%{"command" => command})

    req_headers = [
      {"Content-Type", "application/json"},
      {"Content-Length", "#{byte_size(req_body)}"} | req_headers
    ]

    request = %Request{method: "POST", location: location, headers: req_headers, body: req_body}

    stream_ref = :gun.post(conn, location, req_headers, req_body)

    case :gun.await(conn, stream_ref) do
      {:response, _, 201, _} ->
        :ok

      {:response, _, status, res_headers} ->
        {:error, Err.from_status(request, {status, res_headers}, 201)}
    end
  end

  ## Network calling functions

  # Checks if a new refresh token is needed and obtains it if needed.
  defp check_refresh(state) do
    %{
      refresh_token: refresh_token,
      expires_at: expire_time,
      api_conn: api_conn
    } = state

    if expire_time < DateTime.to_unix(DateTime.utc_now()) + 100 do
      with {:ok, %Refresh{} = refresh} <- do_refresh(api_conn, refresh_token) do
        state
        |> Map.put(:access_token, refresh.access_token)
        |> Map.put(:id_token, refresh.id_token)
        |> Map.put(:refresh_token, refresh.refresh_token)
        |> Map.put(:expires_at, refresh.expires_at)
      end
    else
      {:ok, state}
    end
  end

  # Obtains a new refresh token.
  defp do_refresh(conn, refresh_token) do
    req_body =
      Jason.encode!(%{
        "client_id" => client_id(),
        "client_secret" => client_secret(),
        "grant_type" => "refresh_token",
        "refresh_token" => refresh_token
      })

    request = %Request{method: "POST", location: "/connect/token", headers: [], body: req_body}
    stream_ref = :gun.post(conn, "/connect/token", [], req_body)

    with {:response, :nofin, 200, _headers} <- :gun.await(conn, stream_ref),
         {:ok, body} = :gun.await_body(conn, stream_ref),
         {:ok, json} <- Jason.decode(body) do
      {:ok,
       %Refresh{
         :access_token => json["access_token"],
         :id_token => json["id_token"],
         :refresh_token => json["refresh_token"],
         :expires_at => expiration_timestamp(json["expires_in"])
       }}
    else
      {:response, _, _, _} = response ->
        Error.from_status(request, response, 200, __ENV__.function)

      {:error, %Jason.DecodeError{} = error} ->
        Error.from_body(request, error)

      {:error, error} ->
        Error.from_network(request, error)
    end
  end

  defp get_server_nonce(conn) do
    location = "/api/v2/nonces"
    req_headers = [{"Content-Type", "application/json"}]
    body = ~s({"headers":{"Accept": "application/json"}})

    request = %Request{
      method: "POST",
      location: location,
      headers: req_headers,
      body: body
    }

    stream_ref = :gun.post(conn, location, req_headers, body)

    case :gun.await(conn, stream_ref) do
      {:response, :nofin, 201, res_headers} = response ->
        case List.keyfind(res_headers, "x-unikey-nonce", 0) do
          {"x-unikey-nonce", server_nonce} ->
            {:ok, server_nonce}

          nil ->
            Error.from_headers(request, response, 201, __ENV__.function)
        end

      {:response, _, _, _} = response ->
        Error.from_status(request, response, 201, __ENV__.function)

      {:error, error} ->
        Error.from_network(request, error, __ENV__.function)
    end
  end

  ## Static functions

  defp headers(access_token, server_nonce) do
    [
      {"X-unikey-cnonce", client_nonce()},
      {"X-unikey-context", "Web"},
      {"X-unikey-nonce", server_nonce},
      {"Authorization", "Bearer " <> access_token},
      {"Accept", "application/json"}
    ]
  end

  defp get_cookies(headers) do
    Enum.flat_map(headers, fn {header, content} ->
      if header === "set-cookie" do
        [cookie, _] = String.split(content, ";", parts: 2)
        [cookie]
      else
        []
      end
    end)
  end

  defp www_form_encode(map) do
    Enum.map_join(map, "&", fn {k, v} ->
      URI.encode_www_form(k) <> "=" <> URI.encode_www_form(v)
    end)
  end

  @spec generate_certificate(device_uuid4 :: String.t()) :: binary()
  def generate_certificate(device_uuid4) do
    e = unix_now()

    Base.encode64(
      <<17, 1, 0, 1, 19, 1, 0, 1, 16, 1, 0, 48>> <>
        length_encoded_bytes(18, <<1::32-little>>) <>
        length_encoded_bytes(20, <<e::32-little>>) <>
        length_encoded_bytes(21, <<e::32-little>>) <>
        length_encoded_bytes(22, <<e + 86_400::32-little>>) <>
        <<48, 1, 0, 6>> <>
        length_encoded_bytes(49, <<0::128>>) <>
        length_encoded_bytes(50, uuid_to_binary(device_uuid4)) <>
        length_encoded_bytes(53, :crypto.strong_rand_bytes(32)) <>
        length_encoded_bytes(54, :crypto.strong_rand_bytes(32))
    )
  end

  defp length_encoded_bytes(val, data) do
    <<val::8, byte_size(data)::16-little, data::bytes>>
  end

  defp unix_now() do
    DateTime.utc_now() |> DateTime.to_unix()
  end

  # adds expires_in to utc timestamp
  defp expiration_timestamp(expires_in) do
    unix_now() + expires_in
  end

  # has to be like this for some reason
  defp uuid_to_binary(device_uuid) do
    [i, ii | rest] =
      device_uuid
      |> String.split("-")
      |> Enum.reverse()
      |> Enum.map(fn x -> :binary.decode_hex(x) end)

    [fast_bin_reverse(i), fast_bin_reverse(ii) | rest]
    |> IO.iodata_to_binary()
  end

  defp fast_bin_reverse(bin) do
    bin
    |> :binary.decode_unsigned(:little)
    |> :binary.encode_unsigned(:big)
  end

  ## Configuration functions

  defp username!(opts) do
    Keyword.get(opts, :username) || raise(ArgumentError, "must supply a username")
  end

  defp password!(opts) do
    Keyword.get(opts, :password) || raise(ArgumentError, "must supply a password")
  end

  @doc false
  def __format_cb__(%{state: :closed, reason: reason}) do
    {"Kevo API connection closed: ~p", [reason]}
  end
end
