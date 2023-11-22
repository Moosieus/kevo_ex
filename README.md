# Kevo

A client for Kevo's reverse engineered web API for Elixir, roughly ported from [dcmeglio/pykevoplus](https://github.com/dcmeglio/pykevoplus).

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

```elixir
Finch.start_link(name: KevoFinch)
Kevo.API.start_link(username: "", password: "")
```