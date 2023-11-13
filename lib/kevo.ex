defmodule Kevo do
  def client_secret() do
    "YgA3ADAANgBjADkAZgAxAC0AYwBiAGMAOQAtADQAOAA5ADcALQA5ADMANABiAC0AMgBlAGYAZABmADYANQBjAGIAYgA2ADAA"
  end

  def client_nonce() do
    Base.encode64(:crypto.strong_rand_bytes(64))
  end
end
