# kevo_ex (🚧 Work in progress 🚧)
A client for Kevo's reverse engineered web API, for Elixir. Roughly ported from [dcmeglio/pykevoplus](https://github.com/dcmeglio/pykevoplus).

# Laundry List
- Websocket Behaviour
- Supervisor
- Remove hard-coded module names, expose config options
- Docs, docs, docs
- Write tests (will need mocking)
- Struct-type the responses
- Add credo
- Consider if `login` should be called when initializing `Kevo.API`
  - Argument in favor: Fail in pre-flight vs in-air
  - Argument against: Don't block initialization

## Installation
This package is heavily WIP and isn't yet available on hexdocs.

<!--
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
-->

## Initialization
```elixir
Finch.start_link(name: KevoFinch)
Kevo.API.start_link(username: "", password: "")
```
