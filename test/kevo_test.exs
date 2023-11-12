defmodule KevoTest do
  use ExUnit.Case
  doctest Kevo

  test "greets the world" do
    assert Kevo.hello() == :world
  end
end
