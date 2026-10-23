defmodule Plug.CryptoTest do
  use ExUnit.Case, async: true

  import Plug.Crypto

  test "prunes stacktrace" do
    assert prune_args_from_stacktrace([{:erlang, :+, 2, []}]) == [{:erlang, :+, 2, []}]
    assert prune_args_from_stacktrace([{:erlang, :+, [1, 2], []}]) == [{:erlang, :+, 2, []}]
  end

  test "masks tokens" do
    assert mask(<<0, 1, 0, 1>>, <<0, 1, 1, 0>>) == <<0, 0, 1, 1>>
    assert mask(<<0, 0, 1, 1>>, <<0, 1, 1, 0>>) == <<0, 1, 0, 1>>
  end

  test "compares binaries securely" do
    assert secure_compare(<<>>, <<>>)
    assert secure_compare(<<0>>, <<0>>)

    refute secure_compare(<<>>, <<1>>)
    refute secure_compare(<<1>>, <<>>)
    refute secure_compare(<<0>>, <<1>>)
  end

  test "compares masked binaries securely" do
    assert masked_compare(<<>>, <<>>, <<>>)
    assert masked_compare(<<0>>, <<0>>, <<0>>)
    assert masked_compare(<<0, 1, 0, 1>>, <<0, 0, 1, 1>>, <<0, 1, 1, 0>>)

    refute masked_compare(<<>>, <<1>>, <<0>>)
    refute masked_compare(<<1>>, <<>>, <<0>>)
    refute masked_compare(<<0>>, <<1>>, <<0>>)
  end

  test "non_executable_binary_to_term" do
    value = %{1 => {:foo, ["bar", 2.0, %URI{}, [self() | make_ref()], <<0::4>>]}}
    assert non_executable_binary_to_term(:erlang.term_to_binary(value)) == value

    assert_raise ArgumentError, fn ->
      non_executable_binary_to_term(:erlang.term_to_binary(%{1 => {:foo, [fn -> :bar end]}}))
    end

    assert_raise ArgumentError, fn ->
      non_executable_binary_to_term(<<131, 100, 0, 7, 103, 114, 105, 102, 102, 105, 110>>, [:safe])
    end
  end

  @key "abc123"

  describe "sign and verify" do
    test "token with string" do
      token = sign(@key, "id", 1)
      assert verify(@key, "id", token) == {:ok, 1}
    end

    test "fails on missing token" do
      assert verify(@key, "id", nil) == {:error, :missing}
    end

    test "fails on invalid token" do
      token = sign(@key, "id", 1)

      assert verify(@key, "id", "garbage") ==
               {:error, :invalid}

      assert verify(@key, "not_id", token) ==
               {:error, :invalid}
    end

    test "supports max age in seconds" do
      token = sign(@key, "id", 1)
      assert verify(@key, "id", token, max_age: 1000) == {:ok, 1}
      assert verify(@key, "id", token, max_age: -1000) == {:error, :expired}
      assert verify(@key, "id", token, max_age: 100) == {:ok, 1}
      assert verify(@key, "id", token, max_age: -100) == {:error, :expired}

      token = sign(@key, "id", 1)
      assert verify(@key, "id", token, max_age: 0.1) == {:ok, 1}
      Process.sleep(150)
      assert verify(@key, "id", token, max_age: 0.1) == {:error, :expired}
    end

    test "supports max age in seconds on encryption" do
      token = sign(@key, "id", 1, max_age: 1000)
      assert verify(@key, "id", token) == {:ok, 1}

      token = sign(@key, "id", 1, max_age: -1000)
      assert verify(@key, "id", token) == {:error, :expired}
      assert verify(@key, "id", token, max_age: 1000) == {:ok, 1}

      token = sign(@key, "id", 1, max_age: 0.1)
      Process.sleep(150)
      assert verify(@key, "id", token) == {:error, :expired}
    end

    test "supports :infinity for max age" do
      token = sign(@key, "id", 1)
      assert verify(@key, "id", token, max_age: :infinity) == {:ok, 1}
    end

    test "supports signed_at in seconds" do
      seconds_in_day = 24 * 60 * 60
      day_ago_seconds = System.system_time(:second) - seconds_in_day
      token = sign(@key, "id", 1, signed_at: day_ago_seconds)
      assert verify(@key, "id", token, max_age: seconds_in_day + 1) == {:ok, 1}
      assert verify(@key, "id", token, max_age: seconds_in_day - 1) == {:error, :expired}
    end

    test "passes key_iterations options to key generator" do
      signed1 = sign(@key, "id", 1, signed_at: 0, key_iterations: 1)
      signed2 = sign(@key, "id", 1, signed_at: 0, key_iterations: 2)
      assert signed1 != signed2
    end

    test "passes key_digest options to key generator" do
      signed1 = sign(@key, "id", 1, signed_at: 0, key_digest: :sha256)
      signed2 = sign(@key, "id", 1, signed_at: 0, key_digest: :sha512)
      assert signed1 != signed2
    end

    test "passes key_length options to key generator" do
      signed1 = sign(@key, "id", 1, signed_at: 0, key_length: 16)
      signed2 = sign(@key, "id", 1, signed_at: 0, key_length: 32)
      assert signed1 != signed2
    end

    test "passes the compressed option to term_to_binary" do
      data = List.duplicate("compressible", 100)
      token = sign(@key, "id", data, signed_at: 0, compressed: true)
      [_protected, payload, _signature] = String.split(token, ".")

      assert Base.url_decode64!(payload, padding: false) ==
               :erlang.term_to_binary({data, 0, 86400}, [:compressed])

      assert verify(@key, "id", token, max_age: :infinity) == {:ok, data}
    end

    if System.otp_release() |> String.to_integer() >= 26 do
      test "passes the local option to term_to_binary" do
        data = {:local, self(), make_ref()}
        token = sign(@key, "id", data, signed_at: 0, local: true)
        [_protected, payload, _signature] = String.split(token, ".")

        assert Base.url_decode64!(payload, padding: false) ==
                 :erlang.term_to_binary({data, 0, 86400}, [:local])

        assert verify(@key, "id", token, max_age: :infinity) == {:ok, data}
      end
    end

    test "key defaults" do
      signed1 = sign(@key, "id", 1, signed_at: 0)

      signed2 =
        sign(@key, "id", 1,
          signed_at: 0,
          key_length: 32,
          key_digest: :sha256,
          key_iterations: 1000
        )

      assert signed1 == signed2
    end
  end

  describe "encrypt and decrypt" do
    test "token with string" do
      token = encrypt(@key, "secret", 1)
      assert decrypt(@key, "secret", token) == {:ok, 1}
    end

    test "fails on missing token" do
      assert decrypt(@key, "secret", nil) == {:error, :missing}
    end

    test "fails on invalid token" do
      token = encrypt(@key, "secret", 1)

      assert decrypt(@key, "secret", "garbage") ==
               {:error, :invalid}

      assert decrypt(@key, "not_secret", token) ==
               {:error, :invalid}
    end

    test "supports max age in seconds" do
      token = encrypt(@key, "secret", 1)
      assert decrypt(@key, "secret", token, max_age: 1000) == {:ok, 1}
      assert decrypt(@key, "secret", token, max_age: -1000) == {:error, :expired}
      assert decrypt(@key, "secret", token, max_age: 100) == {:ok, 1}
      assert decrypt(@key, "secret", token, max_age: -100) == {:error, :expired}

      token = encrypt(@key, "secret", 1)
      assert decrypt(@key, "secret", token, max_age: 0.1) == {:ok, 1}
      Process.sleep(150)
      assert decrypt(@key, "secret", token, max_age: 0.1) == {:error, :expired}
    end

    test "supports max age in seconds on encryption" do
      token = encrypt(@key, "secret", 1, max_age: 1000)
      assert decrypt(@key, "secret", token) == {:ok, 1}

      token = encrypt(@key, "secret", 1, max_age: -1000)
      assert decrypt(@key, "secret", token) == {:error, :expired}
      assert decrypt(@key, "secret", token, max_age: 1000) == {:ok, 1}

      token = encrypt(@key, "secret", 1, max_age: 0.1)
      Process.sleep(150)
      assert decrypt(@key, "secret", token) == {:error, :expired}
    end

    test "supports :infinity for max age" do
      token = encrypt(@key, "secret", 1)
      assert decrypt(@key, "secret", token, max_age: :infinity) == {:ok, 1}
    end

    test "supports signed_at in seconds" do
      seconds_in_day = 24 * 60 * 60
      day_ago_seconds = System.os_time(:second) - seconds_in_day
      token = encrypt(@key, "secret", 1, signed_at: day_ago_seconds)
      assert decrypt(@key, "secret", token, max_age: seconds_in_day + 1) == {:ok, 1}

      assert decrypt(@key, "secret", token, max_age: seconds_in_day - 1) ==
               {:error, :expired}
    end

    test "ensures signed_at is not in future while decrypting" do
      token = encrypt(@key, "secret", 1, signed_at: System.os_time(:second) + 31_536_000)
      assert {:error, :invalid} = decrypt(@key, "secret", token)
    end

    test "passes key_iterations options to key generator" do
      signed1 = encrypt(@key, "secret", 1, signed_at: 0, key_iterations: 1)
      signed2 = encrypt(@key, "secret", 1, signed_at: 0, key_iterations: 2)
      assert signed1 != signed2
    end

    test "passes key_digest options to key generator" do
      signed1 = encrypt(@key, "secret", 1, signed_at: 0, key_digest: :sha256)
      signed2 = encrypt(@key, "secret", 1, signed_at: 0, key_digest: :sha512)
      assert signed1 != signed2
    end

    test "supports compressed terms" do
      data = List.duplicate("compressible", 100)
      token = encrypt(@key, "secret", data, compressed: true)
      assert decrypt(@key, "secret", token) == {:ok, data}
    end

    if System.otp_release() |> String.to_integer() >= 26 do
      test "supports local terms" do
        data = {:local, self(), make_ref()}
        token = encrypt(@key, "secret", data, local: true)
        assert decrypt(@key, "secret", token) == {:ok, data}
      end
    end
  end

  describe "decrypt with a non-256-bit key" do
    test "returns :invalid for XChaCha20 tokens instead of raising" do
      token = "XCP." <> Base.url_encode64(:crypto.strong_rand_bytes(41), padding: false)
      assert decrypt(@key, "id", token, key_length: 16) == {:error, :invalid}
      assert decrypt(@key, "id", token, key_length: 24) == {:error, :invalid}
    end
  end

  describe "verified payloads that cannot be decoded" do
    test "returns :invalid when the payload has an unexpected form" do
      secret = Plug.Crypto.KeyGenerator.generate(@key, "id", 1000, 32, :sha256, nil)

      for term <- [%{other: :form}, {:user, 1, :admin}, {:user, :now}, %{data: 1, signed: nil}] do
        token = Plug.Crypto.MessageVerifier.sign(:erlang.term_to_binary(term), secret)
        assert verify(@key, "id", token) == {:error, :invalid}
      end
    end

    if System.otp_release() |> String.to_integer() >= 26 do
      test "returns :invalid when a :local payload comes from another runtime instance" do
        secret = Plug.Crypto.KeyGenerator.generate(@key, "id", 1000, 32, :sha256, nil)
        <<131, 121, hash::32, rest::binary>> = :erlang.term_to_binary({1, 0, 86400}, [:local])
        foreign = <<131, 121, Bitwise.bxor(hash, 1)::32, rest::binary>>
        token = Plug.Crypto.MessageVerifier.sign(foreign, secret)
        assert verify(@key, "id", token) == {:error, :invalid}
      end
    end
  end

  describe "argument validation" do
    test "verify and decrypt return :invalid for non-binary tokens" do
      for token <- [["x"], 123, %{}, :atom] do
        assert verify(@key, "id", token) == {:error, :invalid}
        assert decrypt(@key, "id", token) == {:error, :invalid}
      end
    end

    test "raises ArgumentError on a bad key base, salt or options" do
      for fun <- [&sign/4, &encrypt/4, &verify/4, &decrypt/4] do
        assert_raise ArgumentError, fn -> fun.(nil, "id", "x", []) end
        assert_raise ArgumentError, fn -> fun.(@key, nil, "x", []) end
        assert_raise ArgumentError, fn -> fun.(@key, "id", "x", %{}) end
      end
    end

    test "comparison helpers raise ArgumentError on non-binaries" do
      assert_raise ArgumentError, fn -> secure_compare(nil, "x") end
      assert_raise ArgumentError, fn -> secure_compare(["x"], "x") end
      assert_raise ArgumentError, fn -> masked_compare(nil, "x", "y") end
      assert_raise ArgumentError, fn -> mask("x", "yy") end
    end

    test "argument errors do not put the arguments in the stacktrace" do
      secret = "SECRET-" <> String.duplicate("x", 20)

      funs = [
        fn -> verify(secret, "id", "x", %{}) end,
        fn -> decrypt(secret, "id", "x", %{}) end,
        fn -> sign(secret, nil, 1) end,
        fn -> encrypt(secret, nil, 1) end,
        fn -> secure_compare(nil, secret) end,
        fn -> mask("x", secret) end,
        fn -> Plug.Crypto.MessageVerifier.sign(%{}, secret) end,
        fn -> Plug.Crypto.MessageEncryptor.decrypt(%{}, secret, "") end
      ]

      for fun <- funs do
        try do
          fun.()
          flunk("expected an exception")
        rescue
          e -> refute Exception.format(:error, e, __STACKTRACE__) =~ secret
        end
      end
    end
  end
end
