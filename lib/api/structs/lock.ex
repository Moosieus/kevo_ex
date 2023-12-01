defmodule Kevo.Api.Lock do
  @moduledoc """
  A struct that models a lock json from Kevo.
  """
  defstruct [
    :lock_id,
    :name,
    :firmware,
    :battery_level,
    :locked,
    :jammed,
    :locking,
    :unlocking,
    :brand
  ]
end
