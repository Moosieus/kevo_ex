defmodule Kevo.Common do
  @moduledoc false

  # common functions shared between the http and socket clients.

  def unikey_login_url_base(), do: "identity.unikey.com"
  def unikey_invalid_login_url(), do: "https://identity.unikey.com/account/loginlocal"
  def unikey_api_url_base(), do: "resi-prd-api.unikey.com"

  def unikey_ws_url_base(), do: "resi-prd-ws.unikey.com"

  # Kevo uses ODIC but doesn't depend on `client_secret` for security purposes - It's the same for all clients.
  # In essence, `client_id`, `tenant_id` and `client_secret` are here for standards/ceremony sake.
  # Seriously. Open your network inspector, toggle persist logs, and see for yourself!
  def client_id(), do: "cfced01c-f520-4a32-acac-7c6d2e0da80c"

  def tenant_id(), do: "d2e2d217-61ff-4ac2-98d9-2aedc90ac044"

  def client_secret() do
    "YgA3ADAANgBjADkAZgAxAC0AYwBiAGMAOQAtADQAOAA5ADcALQA5ADMANABiAC0AMgBlAGYAZABmADYANQBjAGIAYgA2ADAA"
  end

  def lock_state_lock(), do: 1
  def lock_state_unlock(), do: 2
  def lock_state_jam(), do: 8
  def lock_state_lock_jam(), do: 9
  def lock_state_unlock_jam(), do: 10

  def command_status_processing(), do: 4
  def command_status_delivered(), do: 7
  def command_status_cancelled(), do: 6
  def command_status_complete(), do: 5

  def client_nonce() do
    Base.encode64(:crypto.strong_rand_bytes(64))
  end

  def gun_opts() do
    %{
      connect_timeout: :timer.seconds(5),
      domain_lookup_timeout: :timer.seconds(5),
      transport: :tls,
      protocols: [:http2],
      tls_handshake_timeout: :timer.seconds(5),
      tls_opts: [
        verify: :verify_peer,
        cacerts: :certifi.cacerts(),
        depth: 3,
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ],
      retry: 0
    }
  end

  def gun_ws_opts() do
    %{
      connect_timeout: :timer.seconds(5),
      domain_lookup_timeout: :timer.seconds(5),
      transport: :tls,
      protocols: [:http],
      tls_handshake_timeout: :timer.seconds(5),
      tls_opts: [
        verify: :verify_peer,
        cacerts: :certifi.cacerts(),
        depth: 3,
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ],
      retry: 1_000_000_000
    }
  end
end
