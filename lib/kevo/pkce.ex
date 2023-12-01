defmodule Kevo.Pkce do
  @doc """
  A short implementation of Pkce for this API.

  Crib https://github.com/RomeoDespres/pkce/blob/master/pkce/__init__.py
  """
  def generate_pkce_pair(verifier_length \\ 128) when verifier_length in 43..128 do
    code_verifier = code_verifier(verifier_length)
    code_challenge = code_challenge(code_verifier)

    {code_verifier, code_challenge}
  end

  def code_verifier(length) do
    :crypto.strong_rand_bytes(length)
    |> Base.url_encode64()
    |> binary_part(0, length)
  end

  def code_challenge(verifier) do
    :crypto.hash(:sha256, verifier)
    |> Base.url_encode64()
    |> binary_slice(0..-2//1)
  end
end
