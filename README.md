# rails_cook

An [Erlang][] library to verify and decrypt [Ruby on Rails][] session cookies.

[Rails]: https://rubyonrails.org/
[Erlang]: https://www.erlang.org

## Summary

Want to reuse a session created by a Ruby on Rails application for an Erlang
service, such as a web API or websocket server?

```erlang
try rails_cook:verify_and_decrypt_cookie(rails5, <<"your rails secret">>, <<"Cookie payload">>) of
  Payload -> jiffy:decode(Payload) % or your other preferred deserialization
catch
  error:bad_sig -> "Invalid session cookie"
end
```

## To Do

This library can get a whole lot better by understanding Rails 3 and 4 sessions,
handling deserialization better, etc.

The API is not stable, and may radically change with updates.
