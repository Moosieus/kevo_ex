# Kevo

A Kevo client for Elixir, ported from [pykevoplus](https://github.com/dcmeglio/pykevoplus).

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

## Planning

Start by initializing kevo_ex in your project:
```elixir
children = [
  {Kevo.Client, [name: MyA2SCli]}
]
```

Or start the client dynamically:
```elixir
Kevo.Client.start_link([name: MyKevoClient])
```

```elixir
Kevo.Client.doThing(blahblahblah)
```

**Problem:**
A package for working with Kevo's unofficial API.

Some requests are done via HTTP and others via Websocket. Hm.

Use Websockex and Finch.

Expose functional primitives if users want to bring their own shit.
