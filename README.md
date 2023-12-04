# kevo_ex (🚧 Work in progress 🚧)
An Elixir client library for Kevo's reverse engineered web API.

Kevo locks were launched in 2016 and discontinued in 2022. While they're unlikely to receive support for [Seam](https://www.seam.co/), the existing web API should (hopefully) remain (relatively) stable.

- Evaluate if the concurrent API is worth keeping
- Fix the query module paths I just broke
- *See if this can't be done any cleaner*

## Todo Before `0.1.0`
- Improve websocket API
- Diagnose websocket quietly dropping
- Add function and module docs
- Use structured logging with format callback functions
  - Provide a format callback in the metadata (straightforward enough)
  - Where do I add the 'middleware' to call said callback? (Maybe `Logger.Translator`)
  - Translator should only affect this application and none others
- Refactor `Kevo.Api.Client` to process messages concurrently

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

## Usage
Add Kevo to your supervision tree:
```elixir
children = [
  {Kevo, [name: Kevo, username: "username", password: "password", websocket_callback: CallbackModule]}
]
```

```elixir
Logger.configure(level: :debug)
Logger.add_translator({Kevo.StateMachineTranslator, :translate})
Kevo.Api.Client.start_link(username: "", password: "")
Kevo.Api.get_locks()
```

## Acknowledgments
Special thanks to the following:
- [dcmeglio](https://github.com/dcmeglio), author of [aiokevoplus](https://github.com/dcmeglio/pykevoplus) (used as reference)
- [Bahnburner](https://github.com/Bahnburner), author of [pykevoplus3](https://github.com/Bahnburner/pykevoplus)
- [cseelye](https://github.com/cseelye), author of [pykevoplus](https://github.com/cseelye/pykevoplus)
- [davidlang42](https://github.com/davidlang42)
- [b3nji](https://github.com/b3nj1)
