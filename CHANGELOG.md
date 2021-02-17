# Changelog

## v1.2.1 (2021-02-17)

  * Add support for Erlang/OTP 24

## v1.2.0 (2020-10-07)

  * Update Elixir requirement to Elixir 1.7+.
  * Fixed a bug that allowed to sign and encrypt stuff with `nil` secret key base and salt.

## v1.1.2 (2020-02-16)

  * Do not key derive empty salts (default to no salt instead).

## v1.1.1 (2020-02-14)

  * Do not expose encryption with salt API.
  * Allow default `:max_age` to be set when signing/encrypting.

## v1.1.0 (2020-02-11)

  * Add high-level `Plug.Crypto.sign/verify` and `Plug.Crypto.encrypt/decrypt`.

## v1.0.0 (2018-10-03)

  * Split up the `plug_crypto` project from Plug as per [elixir-lang/plug#766](https://github.com/elixir-plug/plug/issues/766).
