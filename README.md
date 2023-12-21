# kevo_ex
An Elixir client library for Kevo's reverse engineered web API.

Kevo locks were launched by Kiwkset in 2016 and discontinued in 2022. While they're unlikely to receive support for [Seam](https://www.seam.co/), the existing web API should (hopefully) remain (relatively) stable.

## Installation
Add `:kevo_ex` to your list of dependencies in `mix.exs`:

<!-- BEGIN: VERSION -->
```elixir
def deps do
  [
    {:kevo_ex, "~> 0.2.0"}
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
  ws_callback_module: YourHandlerModule # optional
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
* `:name` - Alias of the top-level supervisor. Can be provided if you intend to run multiple instances of kevo_ex. Defaults to `Kevo`.

* `:username` - Your Kevo username (required).

* `:password` - Your Kevo password (required).

* `:ws_callback_module` - Websocket callback module. Defaults to `nil`.

#### API calls
* `Kevo.get_locks/0` - Retrieves all locks visible to the logged in user.

* `Kevo.get_lock/1` - Retrieves the given lock's state.

* `Kevo.lock/1` - Locks the given lock.

* `Kevo.unlock/1` - Unlocks the given lock.

* `Kevo.get_events/3` - Gets the provided lock's event history. Follows the frontend's paging behavior.

*A `name` atom can be provided as an additional argument. Defaults to `Kevo`.*

#### Websocket events
To receive websocket events, provide a `Kevo.Handler` compliant module using the `ws_callback_module` option. When a message is recevied, `handle_event/1` will be invoked, passing a map of the received JSON. See the page on [example responses](./pages/example_responses.md).

#### Usage notes
- API calls are made to be as concurrently as possible.
- Kevo's websocket accepts no messages and is receive only.
- The websocket will only be opened if `ws_callback_module` is provided.
- This library is unopinionated about how you queue or broker events.

## Acknowledgments
Special thanks to the following:
- [dcmeglio](https://github.com/dcmeglio), author of [aiokevoplus](https://github.com/dcmeglio/pykevoplus) (used as reference)
- [Bahnburner](https://github.com/Bahnburner), author of [pykevoplus3](https://github.com/Bahnburner/pykevoplus)
- [cseelye](https://github.com/cseelye), author of [pykevoplus](https://github.com/cseelye/pykevoplus)
- [davidlang42](https://github.com/davidlang42)
- [b3nji](https://github.com/b3nj1)
