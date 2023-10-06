defmodule Plug.Crypto.KeyGeneratorTest do
  use ExUnit.Case, async: true

  import Bitwise

  @max_length bsl(1, 32) - 1

  test "returns an error for length exceeds max_length" do
    assert_raise ArgumentError, ~r/length must be less than or equal/, fn ->
      generate("secret", "salt", length: @max_length + 1)
    end
  end

  test "returns an error if iterations is not an integer >= 1" do
    for i <- [32.0, -1, nil, "many", :lots] do
      assert_raise ArgumentError, "iterations must be an integer >= 1", fn ->
        generate("secret", "salt", iterations: i)
      end
    end
  end

  test "digest :sha works" do
    key = generate("password", "salt", iterations: 1, length: 20, digest: :sha)
    assert byte_size(key) == 20
    assert to_hex(key) == "0c60c80f961f0e71f3a9b524af6012062fe037a6"

    key = generate("password", "salt", iterations: 2, length: 20, digest: :sha)
    assert byte_size(key) == 20
    assert to_hex(key) == "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"

    key = generate("password", "salt", iterations: 4096, length: 20, digest: :sha)
    assert byte_size(key) == 20
    assert to_hex(key) == "4b007901b765489abead49d926f721d065a429c1"

    key =
      generate(
        "passwordPASSWORDpassword",
        "saltSALTsaltSALTsaltSALTsaltSALTsalt",
        iterations: 4096,
        length: 25,
        digest: :sha
      )

    assert byte_size(key) == 25
    assert to_hex(key) == "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"

    key = generate("pass\0word", "sa\0lt", iterations: 4096, length: 16, digest: :sha)
    assert byte_size(key) == 16
    assert to_hex(key) == "56fa6aa75548099dcc37d7f03425e0c3"

    key = generate("password", "salt", digest: :sha)
    assert byte_size(key) == 32
    assert to_hex(key) == "6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214"

    key = generate("password", "salt")
    assert byte_size(key) == 32
    assert to_hex(key) == "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb3"

    key = generate("password", "salt", iterations: 1000, length: 64, digest: :sha)
    assert byte_size(key) == 64

    assert to_hex(key) ==
             "6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214ce970d912ec2049b04231d47c2eb88506945b26b2325e6adfeeba08895ff9587"
  end

  test "digest :sha224 works" do
    key = generate("password", "salt", iterations: 1, length: 16, digest: :sha224)
    assert byte_size(key) == 16
    assert to_hex(key) == "3c198cbdb9464b7857966bd05b7bc92b"
  end

  test "digest :sha256 works" do
    key = generate("password", "salt", iterations: 1, length: 16, digest: :sha256)
    assert byte_size(key) == 16
    assert to_hex(key) == "120fb6cffcf8b32c43e7225256c4f837"
  end

  test "digest :sha384 works" do
    key = generate("password", "salt", iterations: 1, length: 16, digest: :sha384)
    assert byte_size(key) == 16
    assert to_hex(key) == "c0e14f06e49e32d73f9f52ddf1d0c5c7"
  end

  test "digest :sha512 works" do
    key = generate("password", "salt", iterations: 1, length: 16, digest: :sha512)
    assert byte_size(key) == 16
    assert to_hex(key) == "867f70cf1ade02cff3752599a3a53dc4"
  end

  def generate(secret, salt, opts \\ []) do
    Plug.Crypto.KeyGenerator.generate(secret, salt, opts)
  end

  def to_hex(value), do: Base.encode16(value, case: :lower)
end
