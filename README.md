# kevo_ex (🚧 Work in progress 🚧)
An Elixir client library for Kevo's reverse engineered web API.

Kevo locks were launched in 2016 and discontinued in 2022. While they're unlikely to receive support for [Seam](https://www.seam.co/), the existing web API should (hopefully) remain (relatively) stable.

## Todo
- Implement Websocket Behaviour
- Implement top-level Supervisor
- Remove hard-coded module names and expose more config options
- Document everything
- Write tests (will need mocking)
- Struct-type the responses or provide documented examples
- Properly type the errors in `Kevo.API`
- Maybe rename `Kevo.API` to `Kevo.Api`
- Consider if `login` should be called when initializing `Kevo.API`
  - Argument in favor: Fail in pre-flight vs in-air
  - Argument against: Blocking initialization

*Presently using Finch for the API but may switch entirely to `:gun`...*

## Installation
`kevo_ex` is a work in progress and isn't yet available on hex.

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

## Acknowledgments
Special thanks to the following:
- [dcmeglio](https://github.com/dcmeglio), author of [aiokevoplus](https://github.com/dcmeglio/pykevoplus) (used as reference)
- [Bahnburner](https://github.com/Bahnburner), author of [pykevoplus3](https://github.com/Bahnburner/pykevoplus)
- [cseelye](https://github.com/cseelye), author of [pykevoplus](https://github.com/cseelye/pykevoplus)
- [davidlang42](https://github.com/davidlang42)
- [b3nji](https://github.com/b3nj1)
