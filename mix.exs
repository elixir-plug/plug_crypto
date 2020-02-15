defmodule Plug.Crypto.MixProject do
  use Mix.Project

  @version "1.1.2"
  @description "Crypto-related functionality for the web"

  def project do
    [
      app: :plug_crypto,
      version: @version,
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      name: "Plug.Crypto",
      description: @description,
      docs: [
        main: "Plug.Crypto",
        source_ref: "v#{@version}",
        source_url: "https://github.com/elixir-plug/plug_crypto"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:crypto],
      mod: {Plug.Crypto.Application, []}
    ]
  end

  defp deps do
    [{:ex_doc, "~> 0.21", only: :dev}]
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
