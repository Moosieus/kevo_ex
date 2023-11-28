defmodule Kevo.Api.Error do
  defexception [
    :reason, # :network_error, :unexpected_status, :unexpected_body
    :request, # map of request parameters
    :response, # response received
    :expected, # some expected value, status or header
    :caused_by, # root error given
    :step # interstitial step if applicable
  ]

  # network error
  def message(%__MODULE__{reason: :network_error} = err) do
    step_prefix(err.step) <> "network error: #{inspect(err.caused_by)}"
  end

  # unexpected status
  def message(%__MODULE__{reason: :unexpected_status} = err) do
    {:response, _, status, _} = err.response

    step_prefix(err.step) <> "expected response status #{err.expected}, got: #{status}"
  end

  # unexpected body
  def message(%__MODULE__{reason: :unexpected_body} = err) do
    step_prefix(err.step) <> "invalid json response: #{Jason.DecodeError.message(err.caused_by)}"
  end

  # missing header
  def message(%__MODULE__{reason: :missing_header} = err) do
    {:response, _, _, headers} = err.response

    headers = Enum.map_join(headers, ", ", fn {header, _} -> header end)

    step_prefix(err.step) <> "expected header `#{err.expected}` not present in: [#{headers}]"
  end

  def from_network(request, error, step \\ nil) do
    {:error, %__MODULE__{
      reason: :network_error,
      request: request,
      caused_by: error,
      step: step
    }}
  end

  def from_body(request, %Jason.DecodeError{} = error, step \\ nil) do
    {:error, %__MODULE__{
      reason: :unexpected_body,
      request: request,
      caused_by: error,
      step: step
    }}
  end

  def from_status(request, response, expected, step \\ nil) do
    {:error, %__MODULE__{
      reason: :unexpected_status,
      request: request,
      response: response,
      expected: expected,
      step: step
    }}
  end

  def from_headers(request, response, expected, step \\ nil) do
    {:error, %__MODULE__{
      reason: :missing_header,
      request: request,
      response: response,
      expected: expected,
      step: step
    }}
  end

  defp step_prefix(nil), do: ""
  defp step_prefix({name, arity}), do: "#{name}/#{arity}: "
end
