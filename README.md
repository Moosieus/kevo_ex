# Kevo

A client for Kevo's reverse engineered web API for Elixir, ported from [dcmeglio/pykevoplus](https://github.com/dcmeglio/pykevoplus).

## Todo
- Wrap the REST client in a GenServer to handle authentication and refresh tokens
- Create a behavior for users to bind event handlers to the websocket API

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `kevo_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:kevo_ex, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/kevo_ex>.

```
Finch.start_link(name: KevoFinch)
Kevo.API.start_link(username: "", password: "")
```