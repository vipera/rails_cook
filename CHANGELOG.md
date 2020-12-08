## 0.1.1 (upcoming)

### Bug fixes

- Base the Rails 4 HMAC verification's key generation on the block length of the
  chosen digest algorithm.

### Misc

- Add tests for Rails 4 encryption and verification with ciphers/digest
  algorithms other than AES-256-CBC/SHA1.

## 0.1.0 (2020-12-07)

### Feature changes

- Renamed `rails5` format to `rails_4` and added `rails_5_1` format for decoding
  authenticated & encrypted session cookies used by Rails 5.1+.
- Changed the result of any decrypt method to include the cookie format detected
  to allow disambiguation between randomly decrypted sessions for further
  processing.
- Minimal platform requirement moving up to OTP 22 due to use of new crypto
  API.

## New features

- Added support for Rails 5.1+ session decoding.
- Added `auto` format for automatically infering the Rails version from the
  cookie format.
- Added `infer_rails_version/1` for programatically inferring Rails version from
  a cookie payload.
- Added crypto properties for specifying custom salts, HMAC algorithms and
  ciphers, to support non-default Rails configurations.

## Misc

- Added config for use with rebar3.
- Added .gitignore, GitHub workflow and simple test for ensuring correct
  behaviour.
- Added types and specs for API methods.

## 0.0.1 (2019-10-10)

## New features

- Initial proof of concept library with working Rails 4 decryption and
  verification.
