defmodule Plug.Crypto.MessageEncryptor do
  @moduledoc ~S"""
  `MessageEncryptor` is a simple way to encrypt values which get stored
  somewhere you don't trust.

  The encrypted key, initialization vector, cipher text, and cipher tag
  are base64url encoded and returned to you.

  This can be used in situations similar to the `Plug.Crypto.MessageVerifier`,
  but where you don't want users to be able to determine the value of the payload.

  The current algorithm used is ChaCha20-and-Poly1305.

  ## Example

      iex> secret_key_base = "072d1e0157c008193fe48a670cce031faa4e..."
      ...> encrypted_cookie_salt = "encrypted cookie"
      ...> secret = KeyGenerator.generate(secret_key_base, encrypted_cookie_salt)
      ...>
      ...> data = "José"
      ...> encrypted = MessageEncryptor.encrypt(data, secret, "UNUSED")
      ...> MessageEncryptor.decrypt(encrypted, secret, "UNUSED")
      {:ok, "José"}

  """

  @doc """
  Encrypts a message using authenticated encryption.

  The `sign_secret` is currently only used on decryption
  for backwards compatibility.

  A custom authentication message can be provided.
  It defaults to "A128GCM" for backwards compatibility.
  """
  def encrypt(message, aad \\ "A128GCM", secret, sign_secret)
      when is_binary(message) and (is_binary(aad) or is_list(aad)) and
             byte_size(secret) == 32 and
             is_binary(sign_secret) do
    iv = :crypto.strong_rand_bytes(12)
    {cipher_text, cipher_tag} = block_encrypt(:chacha20_poly1305, secret, iv, {aad, message})
    encode_token("C20P1305", iv, cipher_text, cipher_tag)
  rescue
    e -> reraise e, Plug.Crypto.prune_args_from_stacktrace(__STACKTRACE__)
  end

  @doc """
  Decrypts a message using authenticated encryption.
  """
  def decrypt(encrypted, aad \\ "A128GCM", secret, sign_secret)
      when is_binary(encrypted) and (is_binary(aad) or is_list(aad)) and
             bit_size(secret) in [128, 192, 256] and
             is_binary(sign_secret) do
    case :binary.split(encrypted, ".", [:global]) do
      # Messages from Plug.Crypto v2.x
      [protected, iv, cipher_text, cipher_tag] ->
        with {:ok, "C20P1305"} <- Base.url_decode64(protected, padding: false),
             {:ok, iv} when bit_size(iv) === 96 <- Base.url_decode64(iv, padding: false),
             {:ok, cipher_text} <- Base.url_decode64(cipher_text, padding: false),
             {:ok, cipher_tag} when bit_size(cipher_tag) === 128 <-
               Base.url_decode64(cipher_tag, padding: false),
             plain_text when is_binary(plain_text) <-
               block_decrypt(:chacha20_poly1305, secret, iv, {aad, cipher_text, cipher_tag}) do
          {:ok, plain_text}
        else
          _ -> :error
        end

      # Messages from Plug.Crypto v1.x
      [protected, encrypted_key, iv, cipher_text, cipher_tag] ->
        with {:ok, "A128GCM"} <- Base.url_decode64(protected, padding: false),
             {:ok, encrypted_key} <- Base.url_decode64(encrypted_key, padding: false),
             {:ok, iv} when bit_size(iv) === 96 <- Base.url_decode64(iv, padding: false),
             {:ok, cipher_text} <- Base.url_decode64(cipher_text, padding: false),
             {:ok, cipher_tag} when bit_size(cipher_tag) === 128 <-
               Base.url_decode64(cipher_tag, padding: false),
             {:ok, key} <- aes_gcm_key_unwrap(encrypted_key, secret, sign_secret),
             plain_text when is_binary(plain_text) <-
               block_decrypt(:aes_gcm, key, iv, {aad, cipher_text, cipher_tag}) do
          {:ok, plain_text}
        else
          _ -> :error
        end

      _ ->
        :error
    end
  rescue
    e -> reraise e, Plug.Crypto.prune_args_from_stacktrace(__STACKTRACE__)
  end

  defp block_encrypt(cipher, key, iv, {aad, payload}) do
    cipher = cipher_alias(cipher, bit_size(key))
    :crypto.crypto_one_time_aead(cipher, key, iv, payload, aad, true)
  catch
    :error, :notsup -> raise_notsup(cipher)
  end

  defp block_decrypt(cipher, key, iv, {aad, payload, tag}) do
    cipher = cipher_alias(cipher, bit_size(key))
    :crypto.crypto_one_time_aead(cipher, key, iv, payload, aad, tag, false)
  catch
    :error, :notsup -> raise_notsup(cipher)
  end

  defp cipher_alias(:aes_gcm, 128), do: :aes_128_gcm
  defp cipher_alias(:aes_gcm, 192), do: :aes_192_gcm
  defp cipher_alias(:aes_gcm, 256), do: :aes_256_gcm
  defp cipher_alias(other, _), do: other

  defp raise_notsup(algo) do
    raise "the algorithm #{inspect(algo)} is not supported by your Erlang/OTP installation. " <>
            "Please make sure it was compiled with the correct OpenSSL/BoringSSL bindings"
  end

  # Unwraps an encrypted content encryption key (CEK) with secret and
  # sign_secret using AES GCM mode. Accepts keys of 128, 192, or 256
  # bits based on the length of the secret key.
  #
  # See: https://tools.ietf.org/html/rfc7518#section-4.7
  defp aes_gcm_key_unwrap(wrapped_cek, secret, sign_secret)
       when bit_size(secret) in [128, 192, 256] and is_binary(sign_secret) do
    wrapped_cek
    |> case do
      <<cipher_text::128-bitstring, cipher_tag::128-bitstring, iv::96-bitstring>> ->
        block_decrypt(:aes_gcm, secret, iv, {sign_secret, cipher_text, cipher_tag})

      <<cipher_text::192-bitstring, cipher_tag::128-bitstring, iv::96-bitstring>> ->
        block_decrypt(:aes_gcm, secret, iv, {sign_secret, cipher_text, cipher_tag})

      <<cipher_text::256-bitstring, cipher_tag::128-bitstring, iv::96-bitstring>> ->
        block_decrypt(:aes_gcm, secret, iv, {sign_secret, cipher_text, cipher_tag})

      _ ->
        :error
    end
    |> case do
      cek when bit_size(cek) in [128, 192, 256] -> {:ok, cek}
      _ -> :error
    end
  end

  defp encode_token(protected, iv, cipher_text, cipher_tag) do
    Base.url_encode64(protected, padding: false)
    |> Kernel.<>(".")
    |> Kernel.<>(Base.url_encode64(iv, padding: false))
    |> Kernel.<>(".")
    |> Kernel.<>(Base.url_encode64(cipher_text, padding: false))
    |> Kernel.<>(".")
    |> Kernel.<>(Base.url_encode64(cipher_tag, padding: false))
  end
end
