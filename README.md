# rails_cook

An [Erlang][] library to verify and decrypt [Ruby on Rails][] session cookies.

[Ruby on Rails]: https://rubyonrails.org/
[Erlang]: https://www.erlang.org

## Summary

Want to reuse a session created by a Ruby on Rails application for an Erlang
service, such as a web API or websocket server?

```erlang
try rails_cook:verify_and_decrypt(auto, <<"your rails secret">>, <<"Cookie payload">>) of
  Payload -> jiffy:decode(Payload) % or your other preferred deserialization
catch
  error:bad_sig -> "Invalid session cookie";
  error:unknown_rails_version -> "Unable to determine Rails version"
end
```

The `auto` argument will ask the library to attempt to automatically infer the
Rails version that created the cookie. Rails went though a couple of different
cookie storage formats over the years (supported are 4 and 5.1, 3 or less is not
supported). You can also specify the version yourself:

```erlang
rails_cook:verify_and_decrypt('rails-5.1', <<"your rails secret">>, <<"Cookie payload">>)
```

The utilized decryption/verification and HMAC digest algorithms are configurable,
as they are in Rails, so if you changed the defaults in your Rails setup, you
should be able to get this library to decrypt your cookie. Reasonable defaults
are assumed:

| Purpose                 | Rails 4     | Rails 5     |
| ----------------------- |:-----------:|:-----------:|
| HMAC digest             | SHA-1       | SHA-1       |
| Decryption/Verification | AES-256-CBC | AES-256-GCM |

## To Do

This library currently makes no effort to actually deserialize the cookie
payload. Whether it should do so, or leave that to you is being considered.

Tests and better documentation is on the way.

The API is not yet stable, and may change with updates.
