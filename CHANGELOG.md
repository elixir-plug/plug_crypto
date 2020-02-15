# Changelog

## v1.1.2

  * Do not key derive empty salts (default to no salt instead)

## v1.1.1

  * Do not expose encryption with salt API
  * Allow default `:max_age` to be set when signing/encrypting

## v1.1.0

  * Add high-level `Plug.Crypto.sign/verify` and `Plug.Crypto.encrypt/decrypt`

## v1.0.0

  * Split up the `plug_crypto` project from Plug as per [elixir-lang/plug#766](https://github.com/elixir-plug/plug/issues/766).
