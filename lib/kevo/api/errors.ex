# need to use :reason here
defmodule Kevo.API.LoginError do
  defexception [:step, :request, :response, :expected_status, :network_error, :decode_error]

  def message(%__MODULE__{step: {name, arity}, network_error: err}) do
    "#{name}/#{arity}: network error: #{err}"
  end

  def message(%__MODULE__{step: {name, arity}, decode_error: %Jason.DecodeError{} = err}) do
    "#{name}/#{arity}: could not decode json response: #{Jason.DecodeError.message(err)}"
  end

  def message(%__MODULE__{step: {name, arity}, response: response, expected_status: expected}) do
    "#{name}/#{arity}: expected response status #{response}, got: #{expected}"
  end

  def from_status(step, request, response, expected) do
    %__MODULE__{
      step: step,
      request: request,
      response: response,
      expected_status: expected
    }
  end

  def from_network(step, request, error) do
    %__MODULE__{
      step: step,
      request: request,
      network_error: error
    }
  end

  def from_json(step, request, error) do
    %__MODULE__{
      step: step,
      request: request,
      decode_error: error
    }
  end
end

defmodule Kevo.API.RefreshTokenError do
  defexception [:reason, :request, :response, :network_error, :decode_error]

  @base "get refresh token: "

  def message(%{reason: :network_error, network_error: err}) do
    @base <> "network error: #{err}"
  end

  def message(%{reason: :unexpected_status} = err) do
    %{response: {status, _headers}} = err

    @base <> "expected response status 200 but got: #{status}"
  end

  def message(%{reason: :unexpected_body, decode_error: err}) do
    @base <> "expected valid json body: #{Jason.DecodeError.message(err)}"
  end

  def from_network(request, error) do
    %__MODULE__{
      reason: :network_error,
      request: request,
      network_error: error
    }
  end

  def from_body(request, error) do
    %__MODULE__{
      reason: :unexpected_body,
      request: request,
      decode_error: error
    }
  end

  def from_status(request, response) do
    %__MODULE__{
      reason: :unexpected_status,
      request: request,
      response: response
    }
  end
end

defmodule Kevo.API.GetServerNonceError do
  defexception [:reason, :request, :response, :network_error]

  @base "get server nonce: "

  def message(%__MODULE__{reason: :network_error} = err) do
    @base <> "network error: #{err.network_error}"
  end

  def message(%__MODULE__{reason: :unexpected_status} = err) do
    {status, _headers} = err.response

    @base <> "expected response status 201, got: #{status}"
  end

  def message(%__MODULE__{reason: :nonce_not_found} = err) do
    {_status, headers} = err.response
    headers_str = Enum.map_join(headers, ", ", fn {header, _} -> header end)

    @base <> "expected `x-unikey-nonce` header, got: #{headers_str}"
  end

  def from_network(request, error) do
    %__MODULE__{
      reason: :network_error,
      request: request,
      network_error: error
    }
  end

  def from_headers(request, response) do
    %__MODULE__{
      reason: :nonce_not_found,
      request: request,
      response: response
    }
  end

  def from_status(request, response) do
    %__MODULE__{
      reason: :unexpected_status,
      request: request,
      response: response
    }
  end
end

defmodule Kevo.API.Error do
  defexception [:reason, :request, :response, :expected_status, :received_status, :decode_error, :network_error]

  def message(%__MODULE__{reason: :network_error} = err) do
    "network error: #{err.network_error}"
  end

  def message(%__MODULE__{reason: :unexpected_status} = err) do
    {status, _headers} = err.response

    "expected response status #{err.expected_status}, got: #{status}"
  end

  def from_network(request, error) do
    %__MODULE__{
      reason: :network_error,
      request: request,
      network_error: error
    }
  end

  def from_body(request, error) do
    %__MODULE__{
      reason: :unexpected_body,
      request: request,
      decode_error: error
    }
  end

  def from_status(request, response, expected) do
    %__MODULE__{
      reason: :unexpected_status,
      request: request,
      response: response,
      expected_status: expected
    }
  end
end
