defmodule Kevo.API do
  @moduledoc """
  Constants and functions for interacting with Kevo's API directly
  """

  @unikey_login_url_base "https://identity.unikey.com"
  @unikey_invalid_login_url "https://identity.unikey.com/account/loginlocal"
  @unikey_api_url_base "https://resi-prd-api.unikey.com"

  def client_secret() do
    "YgA3ADAANgBjADkAZgAxAC0AYwBiAGMAOQAtADQAOAA5ADcALQA5ADMANABiAC0AMgBlAGYAZABmADYANQBjAGIAYgA2ADAA"
  end

  def client_id(), do: "cfced01c-f520-4a32-acac-7c6d2e0da80c"
  def tenant_id(), do: "d2e2d217-61ff-4ac2-98d9-2aedc90ac044"

  def lock_state_lock(), do: 1
  def lock_state_unlock(), do: 2
  def lock_state_jam(), do: 8
  def lock_state_lock_jam(), do: 9
  def lock_state_unlock_jam(), do: 10

  def command_status_processing(), do: 4
  def command_status_delivered(), do: 7
  def command_status_cancelled(), do: 6
  def command_status_complete(), do: 5

  defmodule Lock do
    defstruct [
      :lock_id,
      :name,
      :firmware,
      :battery_level,
      :locked,
      :jammed,
      :locking,
      :unlocking,
      :brand
    ]
  end

  defmodule Auth do
    defstruct [
      :access_token,
      :id_token,
      :refresh_token,
      :expires_at,
      :user_id
    ]
  end

  defmodule Refresh do
    defstruct [
      :access_token,
      :id_token,
      :refresh_token,
      :expires_at
    ]
  end

  def login(username, password) do
    {code_challenge, code_verifier} = Kevo.Pkce.generate_pkce_pair()

    with {:ok, login_page_location} <- get_login_url(code_challenge),
         {:ok, login_form} <- get_login_page(login_page_location),
         {verification_token, serialized_client} <- scrape_login_form(login_form),
         {:ok, unikey_redirect_location} <-
           post_login(username, password, serialized_client, verification_token),
         {:ok, code} <- get_unikey_code(unikey_redirect_location),
         {:ok, auth} <- post_jwt(code, code_verifier) do
      auth
    end
  end

  # Login sub-functions

  defp get_login_url(code_challenge) do
    device_id = UUID.uuid4()
    req = Finch.build(:get, auth_url(code_challenge, device_id))

    with {:ok, %Finch.Response{status: 302, headers: headers}} <- Finch.request(req, KevoFinch) do
      {"Location", redirect_location} = List.keyfind!(headers, "Location", 0)
      {:ok, redirect_location}
    end
  end

  defp get_login_page(url) do
    req = Finch.build(:get, url)

    with {:ok, %Finch.Response{status: 200, body: login_form}} <- Finch.request(req, KevoFinch) do
      {:ok, login_form}
    end
  end

  defp post_login(username, password, serialized_client, request_verification_token) do
    req =
      Finch.build(
        :post,
        @unikey_login_url_base <> "#{}/account/login",
        [],
        Jason.encode!(%{
          "SerializedClient" => serialized_client,
          "NumFailedAttempts" => 0,
          "Username" => username,
          "Password" => password,
          "login" => "",
          "__RequestVerificationToken" => request_verification_token
        })
      )

    with {:ok, %Finch.Response{status: 302, headers: headers}} <- Finch.request(req, KevoFinch) do
      {"Location", redirect_location} = List.keyfind(headers, "Location", 0)

      case List.keyfind(headers, "Location", 0) do
        # need to type/kind this
        nil -> {:error, :invalid_login}
        _ -> {:ok, redirect_location}
      end
    end
  end

  defp get_unikey_code(location) do
    req = Finch.build(:get, @unikey_login_url_base <> location)

    with {:ok, %Finch.Response{status: 302, headers: headers}} <- Finch.request(req, KevoFinch) do
      {"Location", redirect_location} = List.keyfind(headers, "Location", 0)
      %URI{fragment: fragment} = URI.parse(redirect_location)
      %URI{query: query} = URI.parse(fragment)
      %{"code" => code} = URI.decode_query(query)
      {:ok, code}
    end
  end

  defp post_jwt(code, code_verifier) do
    req =
      Finch.build(
        :post,
        @unikey_login_url_base <> "/connect/token",
        [],
        Jason.encode!(%{
          "client_id" => client_id(),
          "client_secret" => client_secret(),
          "code" => code,
          "code_verifier" => code_verifier,
          "grant_type" => "authorization_code",
          "redirect_uri" => "https://mykevo.com/#/token"
        })
      )

    with {:ok, %Finch.Response{status: 200, body: body}} <- Finch.request(req, KevoFinch) do
      %{
        "access_token" => access_token,
        "id_token" => id_token,
        "refresh_token" => refresh_token,
        "expires_in" => expires_in
      } = Jason.decode!(body)

      expires_at = expires_at(expires_in)

      %{"sub" => user_id} = JOSE.decode(id_token)

      {:ok,
       %Kevo.API.Auth{
         :access_token => access_token,
         :id_token => id_token,
         :refresh_token => refresh_token,
         :expires_at => expires_at,
         :user_id => user_id
       }}
    end
  end

  defp auth_url(code_challenge, device_uuid4) do
    certificate = generate_certificate(device_uuid4) |> Base.encode64()
    client_id = client_id()
    state = :crypto.hash(:md5, :crypto.strong_rand_bytes(32))

    @unikey_login_url_base <>
      "/connect/authorize/?" <>
      URI.encode_query(%{
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
      })
  end

  defp scrape_login_form(html) do
    %{"token" => request_verification_token} =
      Regex.named_captures(
        ~r/<input.* name="__RequestVerificationToken".* value="(?<token>.*)"/,
        html
      )

    %{"token" => serialized_client} =
      Regex.named_captures(~r/<input.* name="SerializedClient".* value="(?<token>.*)"/, html)

    {request_verification_token, serialized_client}
  end

  # API calls

  def get_locks(access_token) do
    with {:ok, snonce} <- get_server_nonce(),
         headers <- headers(access_token, snonce) do
      "foop #{headers}"
    end
  end

  # Doing Oauth 2.0
  @spec request(request :: %Finch.Request{}, auth :: %Kevo.API.Auth{}) :: {:ok, %Finch.Response{}}
  def request(request, %Kevo.API.Auth{
        access_token: access_token,
        refresh_token: refresh_token,
        expires_at: expires_at
      }) do
    case expires_at < unix_now() + 100 do
      true ->
        "foo"

      false ->
        # hard stop here: Need to encapsulate this stuff into a GenServer to wrap the authentication state.
        with {:ok, refresh} <- post_refresh(refresh_token) do
          "bar"
        end
    end

    headers = headers(access_token, Kevo.API.get_server_nonce())
  end

  # need to reauthenticate on expired refresh tokens
  def post_refresh(refresh_token) do
    req =
      Finch.build(
        :post,
        @unikey_login_url_base <> "/connect/token",
        [],
        Jason.encode!(%{
          "client_id" => client_id(),
          "client_secret" => client_secret(),
          "grant_type" => "refresh_token",
          "refresh_token" => refresh_token
        })
      )

    with {:ok, %Finch.Response{status: 200, body: body}} <- Finch.request(req, KevoFinch) do
      %{
        "access_token" => access_token,
        "id_token" => id_token,
        "refresh_token" => refresh_token,
        "expires_in" => expires_in
      } = Jason.decode!(body)

      {:ok,
       %Kevo.API.Refresh{
         :access_token => access_token,
         :id_token => id_token,
         :refresh_token => refresh_token,
         :expires_at => expires_at(expires_in)
       }}
    end
  end

  # Helper Functions

  defp headers(access_token, server_nonce) do
    %{
      "X-unikey-cnonce" => Kevo.client_nonce(),
      "X-unikey-context" => "Web",
      "X-unikey-nonce" => server_nonce,
      "Authorization" => "Bearer " <> access_token,
      "Accept" => "application/json"
    }
  end

  @spec generate_certificate(device_uuid4 :: binary()) :: binary()
  def generate_certificate(device_uuid4) do
    e = DateTime.utc_now() |> DateTime.to_unix()

    Base.encode64(
      <<17, 1, 0, 1, 19, 1, 0, 1, 16, 1, 0, 48>> <>
        length_encoded_byte(18, <<1::32-little>>) <>
        length_encoded_byte(20, <<e::32-little>>) <>
        length_encoded_byte(21, <<e::32-little>>) <>
        length_encoded_byte(22, <<e + 86400::32-little>>) <>
        <<48, 1, 0, 6>> <>
        length_encoded_byte(49, <<0::128>>) <>
        length_encoded_byte(50, UUID.string_to_binary!(device_uuid4)) <>
        length_encoded_byte(53, :crypto.strong_rand_bytes(32)) <>
        length_encoded_byte(54, :crypto.strong_rand_bytes(32))
    )
  end

  defp length_encoded_byte(val, data) do
    <<val::8, byte_size(data)::16, data::bytes>>
  end

  def get_server_nonce() do
    body =
      Jason.encode!(%{
        "headers" => %{"Accept" => "application/json"}
      })

    req =
      Finch.build(
        :post,
        @unikey_api_url_base <> "/api/v2/nonces",
        [{"Content-Type", "application/json"}],
        body
      )

    with {:ok, %Finch.Response{status: 200, headers: headers}} <- Finch.request(req, KevoFinch) do
      {"x-unikey-nonce", server_nonce} = List.keyfind(headers, "x-unikey-nonce", 0)
      {:ok, server_nonce}
    end
  end

  defp unix_now() do
    DateTime.utc_now() |> DateTime.to_unix()
  end

  # adds expires_in to utc timestamp
  defp expires_at(expires_in) do
    DateTime.utc_now()
    |> DateTime.to_unix()
    |> DateTime.add(expires_in)
  end
end
