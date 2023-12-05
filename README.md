# kevo_ex
An Elixir client library for Kevo's reverse engineered web API.

Kevo locks were launched in 2016 and discontinued in 2022. While they're unlikely to receive support for [Seam](https://www.seam.co/), the existing web API should (hopefully) remain (relatively) stable.

## Installation
Add `:kevo_ex` to your list of dependencies in `mix.exs`:

<!-- BEGIN: VERSION -->
```elixir
def deps do
  [
    {:kevo_ex, "~> 0.1.0"}
  ]
end
```
<!-- END: VERSION -->

Documentation is available on [HexDocs](https://hexdocs.pm/kevo_ex/readme.html) and may also be generated with [ExDoc](https://github.com/elixir-lang/ex_doc).

## Usage
Add `Kevo` to your app's supervision tree:
```elixir
kevo_opts = [
  name: Kevo,
  username: "username",
  password: "password",
  websocket_callback: YourHandlerModule # optional
]

children = [
  {Kevo, kevo_otps}
]
```

Or start the client dynamically:
```elixir
Kevo.start_link([name: Kevo, username: "username", password: "password"])
```

#### Configuration
The following configuration options are available:

`:name` - The `name` (aka alias) of the top-level supervisor (required).

`:username` - Your Kevo account username (required).

`:password` - Your Kevo account password (required).

`:websocket_callback` - Websocket callback module (optional).

#### API calls
For querying Kevo's HTTP API, see the available functions in the `Kevo` module.

#### Websocket events
To receive websocket events, provide a `Kevo.Handler` compliant module using the `websocket_callback` option. When a message is recevied, `handle_event/1` will be invoked, passing a map of the received JSON. See the page on [example responses](./pages/example_responses.md).

#### Usage notes
- API calls are made to be as non-blocking as possible.
- Kevo's websocket accepts no messages and is receive only.
- The websocket will only be opened if `websocket_callback` is provided.
- This library is unopinionated about how you queue or broker events.
- `kevo_ex` uses `:gen_statem` internally.

## Acknowledgments
Special thanks to the following:
- [dcmeglio](https://github.com/dcmeglio), author of [aiokevoplus](https://github.com/dcmeglio/pykevoplus) (used as reference)
- [Bahnburner](https://github.com/Bahnburner), author of [pykevoplus3](https://github.com/Bahnburner/pykevoplus)
- [cseelye](https://github.com/cseelye), author of [pykevoplus](https://github.com/cseelye/pykevoplus)
- [davidlang42](https://github.com/davidlang42)
- [b3nji](https://github.com/b3nj1)
