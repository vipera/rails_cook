[![GitHub Actions][actions badge]][actions]
![GitHub License][license badge]

# rails_cook

A library to verify and decrypt [Ruby on Rails][] session cookies written in
[Erlang][].

[Ruby on Rails]: https://rubyonrails.org/
[Erlang]: https://www.erlang.org

## Requirements

Requires Erlang/OTP >= 22.

Erlang/OTP >= 22 is required due to the use of the new crypto API.

## Summary

Want to reuse a session created by a Ruby on Rails application for an Erlang
service, such as a web API or websocket server?

```erlang
try rails_cook:verify_and_decrypt(auto, <<"secret key base">>, <<"cookie">>) of
  {RailsVersion, CookiePayload} -> jiffy:decode(CookiePayload) % or your preferred deserialization
catch
  error:bad_sig -> "Invalid session cookie";
  error:unknown_rails_version -> "Unable to determine Rails version"
end
```

The `auto` argument will ask the library to attempt to automatically infer the
Rails version that created the cookie. Rails went though a couple of different
cookie storage formats over the years (supported are 4 and 5.1. Version 3 or
less is not supported due to the cookie payload being serialized with Ruby
object marshaling).

Instead of `auto`, you can specify the version explicitly:

```erlang
rails_cook:verify_and_decrypt(rails_5_1, <<"secret key base">>, <<"cookie">>)
```

The utilized decryption/verification and HMAC digest algorithms are
configurable, as they are in Rails, so if you changed the defaults in your Rails
setup, you should be able to get this library to decrypt your cookie. Reasonable
defaults are assumed:

| Purpose                 | Rails 4     | Rails 5     |
| ----------------------- |:-----------:|:-----------:|
| HMAC digest             | SHA-1       | SHA-1       |
| Decryption/Verification | AES-256-CBC | AES-256-GCM |

To override any property, just pass an additional proplist to any of the
functions. All exported functions have a variant that expects a proplist as
the final argument:

```erlang
try rails_cook:verify_and_decrypt(rails_4,
                                  <<"secret key base">>,
                                  <<"cookie">>,
                                  [{'hmac_hash_alg', md5}]) of
  % ...
catch
  % ...
end
```

A full list of settings is given here:

| Setting                               | Description                                                                            |
| ------------------------------------- | -------------------------------------------------------------------------------------- |
| `hmac_hash_alg`                       | Sets the HMAC digest algorithm to be used for signed cookies<br>Rails config setting: `config.action_dispatch.signed_cookie_digest`<br>Default: `sha`|
| `cipher_alg`                          | Sets the cipher to be used for decryption/verification of encrypted cookies<br>Rails config setting: `config.action_dispatch.encrypted_cookie_cipher`<br>Default: `aes_256_cbc`, `aes_256_gcm`|
| `encrypted_cookie_salt`               | Cookie salt (encrypted cookies)<br>Rails config setting: `config.action_dispatch.encrypted_cookie_salt`<br>Default: `<<"encrypted cookie">>`|
| `encrypted_signed_cookie_salt`        | Cookie salt (encrypted & signed cookies)<br>Rails config setting: `config.action_dispatch.encrypted_signed_cookie_salt`<br>Default: `<<"signed encrypted cookie">>`|
| `authenticated_encrypted_cookie_salt` | Cookie salt (authenticated & encrypted cookies)<br>Rails config setting: `config.action_dispatch.authenticated_encrypted_cookie_salt`<br>Default: `<<"authenticated encrypted cookie">>`|

## To Do

This library currently makes no effort to actually deserialize the cookie
payload. Whether it should do so, or leave that to you is being considered.

The API is not yet stable, and may change with updates.

<!-- Badges -->
[actions badge]: https://img.shields.io/github/workflow/status/vipera/rails_cook/CI?style=flat-square
[actions]: https://github.com/vipera/rails_cook/actions?query=workflow%3ACI
[license badge]: https://img.shields.io/github/license/vipera/rails_cook?style=flat-square
