# I think this is broadly a better direction

defmodule Kevo.API.LoginError do
  alias Kevo.API.LoginError
  defexception [:step, :request, :response, :expected_status, :network_error, :decode_error]

  def message(%{step: {name, arity}, network_error: %Finch.Error{} = err}) do
    "#{name}/#{arity}: unexpected network error: #{Finch.Error.message(err)}"
  end

  def message(%{step: {name, arity}, decode_error: %Jason.DecodeError{} = err}) do
    "#{name}/#{arity}: could not decode json response: #{Jason.DecodeError.message(err)}"
  end

  def message(%{step: {name, arity}, response: %Finch.Response{status: got}, expected_status: expected}) do
    "#{name}/#{arity}: expected response status #{got}, got: #{expected}"
  end

  def from_status(step, request, response, expected) do
    %LoginError{
      step: step,
      request: request,
      response: response,
      expected_status: expected
    }
  end

  def from_network(step, request, error) do
    %LoginError{
      step: step,
      request: request,
      network_error: error
    }
  end

  def from_json(step, request, error) do
    %LoginError{
      step: step,
      request: request,
      decode_error: error
    }
  end
end

# There's too many errors here and furthermore, most of them are for internal function calls.
# Errors are abstraction leaks unto themselves. That's to say if an internal step fails, the details must be presented to the caller.
# That considered, the error should be structured in the context of the calling function, and that's actionable.
# That's to say a failed invocation of "login" should result in a `%Kevo.API.LoginError{}`

# If the royal "we" define success for a function, we should describe the failure in kind.
# That's to say, if a response should return 302 and it doesn't, our message should say "expected 302, got ___".

defmodule Kevo.API.RefreshTokenError do
  defexception [:network_error, :request, :response, :decode_error]

  def message(%{network_error: err}) do
    "failed to send request: #{Finch.Error.message(err)}"
  end

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200 but got: #{status}"
  end

  def message(%{decode_error: err}) do
    "got expected response but couldn't decode json body: #{Jason.DecodeError.message(err)}"
  end
end

defmodule Kevo.API.GetServerNonceError do
  defexception [:network_error, :request, :response, :headers]

  def message(%{network_error: err}) do
    "failed to send: #{Finch.Error.message(err)}"
  end

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 201, got: #{status}"
  end

  def message(%{headers: headers}) do
    "expected `x-unikey-nonce` in headers: #{Enum.map_join(headers, ", ", fn {header, _} -> header end)}"
  end
end

defmodule Kevo.API.GetLocksError do
  defexception [:network_error, :request, :response, :decode_error]

  def message(%{network_error: %Finch.Error{} = err}) do
    "request to get locks failed to send: #{Finch.Error.message(err)}"
  end

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end

  def message(%{decode_error: %Jason.DecodeError{} = err}) do
    "could not decode json body from successful response: #{Jason.DecodeError.message(err)}"
  end
end

defmodule Kevo.API.GetLockEventsError do
  defexception [:network_error, :request, :response, :decode_error]

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end
end

defmodule Kevo.API.GetLoginUrlError do
  defexception [:network_error, :request, :response]

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end
end

defmodule Kevo.API.GetLoginPageError do
  defexception [:network_error, :request, :response]

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end
end

defmodule Kevo.API.SubmitLoginError do
  defexception [:network_error, :request, :response]

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end
end

defmodule Kevo.API.GetUnikeyCodeError do
  defexception [:network_error, :request, :response]

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end
end

defmodule Kevo.API.PostJWTError do
  defexception [:network_error, :request, :response]

  def message(%{response: %Finch.Response{status: status}}) do
    "expected response status 200, got: #{status}"
  end
end
