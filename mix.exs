defmodule Plug.Crypto.MixProject do
  use Mix.Project

  @version "1.0.0"
  @description "Crypto-related functionality for the web, used by Plug."

  def project do
    [
      app: :plug_crypto,
      version: @version,
      elixir: "~> 1.4",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      name: "Plug.Crypto",
      description: @description,
      docs: [
        extras: ["README.md"],
        main: "readme",
        source_ref: "v#{@version}",
        source_url: "https://github.com/elixir-plug/plug"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp deps do
    [{:ex_doc, "~> 0.19.1", only: :dev}]
  end

  defp package do
    %{
      licenses: ["Apache 2"],
      maintainers: [
        "Aleksei Magusev",
        "Andrea Leopardi",
        "Eric Meadows-Jönsson",
        "Gary Rennie",
        "José Valim"
      ],
      links: %{"GitHub" => "https://github.com/elixir-plug/plug_crypto"},
      files: ["lib", "mix.exs", "README.md", "CHANGELOG.md"]
    }
  end
end
