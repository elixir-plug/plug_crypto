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
  end
end
