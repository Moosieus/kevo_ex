defmodule Kevo.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/moosieus/kevo_ex"

  def project do
    [
      app: :kevo_ex,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      description: "An Elixir client library for Kevo's reverse engineered web API.",
      deps: deps(),
      docs: docs(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:uuid, "~> 1.1"},
      {:jason, "~> 1.4"},
      {:html_entities, "~> 0.5"},
      {:joken, "~> 2.5"},
      {:gun, "~> 2.0"},
      {:ex_doc, "~> 0.30", only: :dev, runtime: false},
      {:credo, "~> 1.4", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.1", only: [:dev], runtime: false},
      {:certifi, "~> 2.12"}
    ]
  end

  defp docs do
    [
      name: "Kevo_ex",
      source_url: @source_url,
      homepage_url: @source_url,
      main: "readme",
      source_ref: "main",
      extras: [
        "README.md",
        "pages/example_responses.md"
      ],
      groups_for_modules: [
        "Developer Interface": [
          Kevo,
          Kevo.Handler
        ],
        "Exceptions": [
          Kevo.ApiError
        ]
      ]
    ]
  end

  defp package do
    [
      name: "kevo_ex",
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
