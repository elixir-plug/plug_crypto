defmodule Plug.Crypto.MessageEncryptorTest do
  use ExUnit.Case, async: true

  alias Plug.Crypto.MessageEncryptor, as: ME
  alias Plug.Crypto.{MessageEncryptor, KeyGenerator}
  doctest MessageEncryptor

  @right String.duplicate("abcdefgh", 4)
  @wrong String.duplicate("12345678", 4)

  test "it encrypts/decrypts a message" do
    data = <<0, "hełłoworld", 0>>
    encrypted = ME.encrypt(data, "right aad", @right, "UNUSED")
    assert ME.decrypt(encrypted, "right aad", @wrong, "UNUSED") == :error
    assert ME.decrypt(encrypted, "wrong aad", @right, "UNUSED") == :error
    assert ME.decrypt(encrypted, "right aad", @right, "UNUSED") == {:ok, data}
  end

  test "it encrypts/decrypts with iodata aad" do
    data = <<0, "hełłoworld", 0>>
    encrypted = ME.encrypt(data, ["right", ?\s, "aad"], @right, @right)
    assert ME.decrypt(encrypted, ["right", ?\s, "aad"], @right, @right) == {:ok, data}
  end

  @old_message "QTEyOEdDTQ.L85cCXPvSqswNJoxmP5QTopFY83qCPj9czxkwct8b0HDHdC8Qwruhkq3SWw.mmqfbc2dfaMMi6Xi.n1qvYhAUYI0r7-QB6Vw.0jV2tT3U-AQMAQSch2rNsw"

  test "it decodes messages from earlier versions" do
    data = <<0, "hełłoworld", 0>>
    assert ME.decrypt(@old_message, "right aad", @right, @right) == {:ok, data}
    assert ME.decrypt(@old_message, "wrong aad", @right, @right) == :error
    assert ME.decrypt(@old_message, "right aad", @wrong, @right) == :error
    assert ME.decrypt(@old_message, "right aad", @right, @wrong) == :error
    assert ME.decrypt(@old_message, "right aad", @wrong, @wrong) == :error
  end
end
