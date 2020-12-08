%%% rails_cook
%%% Rails cookie utilities

-module(rails_cook).
-export([infer_rails_version/1,
         infer_rails_version/2,
         verify/3,
         verify/4,
         decrypt/3,
         decrypt/4,
         verify_and_decrypt/3,
         verify_and_decrypt/4]).

-define(ENCRYPTED_COOKIE_SALT, <<"encrypted cookie">>).
-define(ENCRYPTED_SIGNED_COOKIE_SALT, <<"signed encrypted cookie">>).
-define(AUTHENTICATED_ENCRYPTED_COOKIE_SALT, <<"authenticated encrypted cookie">>).

-type rails_version() :: rails_4 | rails_5_1.
-type cookie() :: binary().
-type secret_key_base() :: binary().

-type crypto_opts() :: [ crypto_opt() ].
-type crypto_opt() :: { hmac_hash_alg, atom() }
                    | { cipher_alg, atom() }
                    | { encrypted_cookie_salt, binary() }
                    | { encrypted_signed_cookie_salt, binary() }
                    | { authenticated_encrypted_cookie_salt, binary() }.

-type verify_result() :: verify_error() | { ok, binary() }.
-type verify_error() :: bad_sig.

-type decrypt_result() :: { rails_version(), binary() }.

%% Compatibility macros for supporting multiple OTP versions
-if(?OTP_RELEASE >= 23).
  %% OTP 23 provides crypto_one_time/5 with 'pcks_padding' padding type.
  -define(rails4Decrypt(CipherAlg, EncCookieKey, IV, Ciphertext),
    begin
    ((fun () ->
        case crypto:crypto_one_time(CipherAlg, EncCookieKey, IV, Ciphertext,
                                    [{encrypt, false}, {padding, pkcs_padding}]) of
          {_, _, Description} -> {error, Description};
          Result -> Result
        end
      end)())
    end).
-elif(?OTP_RELEASE >= 22).
  %% Workaround for OTP 22 - manually remove PCKS7 padding after decryption
  -define(rails4Decrypt(CipherAlg, EncCookieKey, IV, Ciphertext),
    begin
    ((fun () ->
        case crypto:crypto_one_time(CipherAlg, EncCookieKey, IV, Ciphertext, false) of
          {_, _, Description} -> {error, Description};

          % Manually remove PKCS7 padding
          Result -> binary:part(Result, 0, byte_size(Result) - binary:last(Result))
        end
      end)())
    end).
-else.
  -error("Minimum of Erlang/OTP 22 is required to use rails_cook.").
-endif.

%%% PUBLIC API

-spec infer_rails_version(Cookie) -> rails_version()
      when Cookie :: cookie().

%% Attempts to automatically determine the rails version from the cookie format
infer_rails_version(Cookie) ->
  infer_rails_version(Cookie, []).

-spec infer_rails_version(Cookie, CryptoOpts) -> rails_version()
      when Cookie :: cookie(),
           CryptoOpts :: crypto_opts().

%% Attempts to automatically determine the rails version from the cookie format
infer_rails_version(Cookie, _Properties) when is_binary(Cookie) ->
  CookieParts = binary:split(uri_decode(Cookie), <<"--">>, [global]),
  case erlang:length(CookieParts) - 1 of
    1 -> rails_4;
    2 -> rails_5_1;
    _ -> unknown
  end.

-spec decrypt(CookieFormat, SecretKeyBase, Cookie) -> decrypt_result()
      when CookieFormat :: rails_version() | auto,
           SecretKeyBase :: secret_key_base(),
           Cookie :: cookie().

decrypt(RailsVersion, RailsKey, Cookie) ->
  decrypt(RailsVersion, RailsKey, Cookie, []).

-spec decrypt(CookieFormat, SecretKeyBase, Cookie, CryptoOpts) -> decrypt_result()
      when CookieFormat :: rails_version() | auto,
           SecretKeyBase :: secret_key_base(),
           Cookie :: cookie(),
           CryptoOpts :: crypto_opts().

%% Automatically infers Rails version from the cookie format and decrypts the
%% cookie
decrypt(auto, RailsKey, Cookie, Properties) ->
  RailsVersion = infer_rails_version(Cookie),
  decrypt(RailsVersion, RailsKey, Cookie, Properties);

decrypt(unknown, _RailsKey, _Cookie, _Properties) ->
  erlang:error(unknown_rails_version);

%% Since 5.1.0, Rails is leveraging AEAD (AES-256-GCM cipher) for faster
%% encryption/decryption and verification, in a single step.
%%
%% <cookie-payload> ::= <cipher-text> "--" <cipher-iv> "--" <cipher-auth-tag>
decrypt(rails_5_1, RailsKey, Cookie, Properties) ->
  [Ciphertext, IV, AuthTag] = lists:map(fun base64:decode/1,
                                        binary:split(uri_decode(Cookie),
                                                     <<"--">>, [global])),
  case byte_size(AuthTag) of
    16 -> ok;
    _ -> erlang:error(invalid_auth_tag_size)
  end,
  CookieSalt = case get_authenticated_encrypted_cookie_salt(Properties) of
    undefined -> ?AUTHENTICATED_ENCRYPTED_COOKIE_SALT;
    Salt -> Salt
  end,
  CipherAlg = case get_cipher_alg(Properties) of
    undefined -> aes_256_gcm;
    Alg -> Alg
  end,
  {ok, KeyLength} = maps:find(key_length, crypto:cipher_info(CipherAlg)),
  EncCookieKey = get_pbkdf2_key(RailsKey, CookieSalt, KeyLength),
  case crypto:crypto_one_time_aead(CipherAlg, EncCookieKey, IV,
                                   Ciphertext, <<>>, AuthTag, false) of
    error -> erlang:error(bad_sig);
    Plaintext -> {rails_5_1, Plaintext}
  end;

%% Since Rails 4.0, the cookie data is base64 encoded and is a PAYLOAD--IV pair,
%% where payload is encrypted with AES-256-CBC block cipher.
%%
%% <verified-payload> ::= <cipher-text> "--" <cipher-iv>
decrypt(rails_4, RailsKey, Cookie, Properties) ->
  [Ciphertext, IV] = lists:map(fun base64:decode/1,
                               binary:split(uri_decode(Cookie), <<"--">>)),
  CookieSalt = case get_encrypted_cookie_salt(Properties) of
    undefined -> ?ENCRYPTED_COOKIE_SALT;
    Salt -> Salt
  end,
  CipherAlg = case get_cipher_alg(Properties) of
    undefined -> aes_256_cbc;
    Alg -> Alg
  end,
  {ok, KeyLength} = maps:find(key_length, crypto:cipher_info(CipherAlg)),
  EncCookieKey = get_pbkdf2_key(RailsKey, CookieSalt, KeyLength),
  case ?rails4Decrypt(CipherAlg, EncCookieKey, IV, Ciphertext) of
    error -> erlang:error(cannot_decrypt);
    Plaintext -> {rails_4, Plaintext}
  end.

-spec verify(CookieFormat, SecretKeyBase, Cookie) -> verify_result()
      when CookieFormat :: rails_version() | auto,
           SecretKeyBase :: secret_key_base(),
           Cookie :: cookie().

verify(RailsVersion, RailsKey, Cookie) ->
  verify(RailsVersion, RailsKey, Cookie, []).

-spec verify(CookieFormat, SecretKeyBase, Cookie, CryptoOpts) -> verify_result()
      when CookieFormat :: rails_version() | auto,
           SecretKeyBase :: secret_key_base(),
           Cookie :: cookie(),
           CryptoOpts :: crypto_opts().

%% Automatically infers Rails version from the cookie format and verifies the
%% cookie
verify(auto, RailsKey, Cookie, Properties) ->
  RailsVersion = infer_rails_version(Cookie),
  verify(RailsVersion, RailsKey, Cookie, Properties);

verify(unknown, _RailsKey, _Cookie, _Properties) ->
  erlang:error(unknown_rails_version);

%% For Rails >= 5.1.0 A "null verifier" is used, i.e. no verification is done by
%% hand, as it is handled by the cipher. The payload is base64 encoded.
verify(rails_5_1, _RailsKey, Cookie, _Properties) ->
  {ok, Cookie};

%% Rails < 5.1.0 uses a HMAC to prove the authenticity of a cookie payload
%%
%% <cookie-payload> ::= <verified-payload-b64> "--" <hmac>
verify(rails_4, RailsKey, Cookie, Properties) ->
  %% Rails 4 cookie is HMAC-signed at the outmost layer: PAYLOAD--SIGNATURE
  [CookieData, Digest] = binary:split(uri_decode(Cookie), <<"--">>),
  %% Verify that the signature is correct
  CookieSalt = case get_encrypted_signed_cookie_salt(Properties) of
    undefined -> ?ENCRYPTED_SIGNED_COOKIE_SALT;
    Salt -> Salt
  end,
  HmacHashAlg = case get_hmac_hash_alg(Properties) of
    undefined -> sha;
    Alg -> Alg
  end,
  {ok, HashBlockSize} = maps:find(block_size, crypto:hash_info(HmacHashAlg)),
  SigEncCookieKey = get_pbkdf2_key(RailsKey, CookieSalt, HashBlockSize),
  <<Hmac:160/integer>> = crypto:mac(hmac, HmacHashAlg, SigEncCookieKey, CookieData),
  HexHmac = list_to_binary(lists:flatten(io_lib:format("~40.16.0b", [Hmac]))),
  if
    HexHmac =:= Digest -> % signature OK
      {ok, base64:decode(CookieData)};
    HexHmac =/= Digest -> % invalid signature
      bad_sig
  end.

-spec verify_and_decrypt(CookieFormat, SecretKeyBase, Cookie, CryptoOpts) -> decrypt_result()
      when CookieFormat :: rails_version() | auto,
           SecretKeyBase :: secret_key_base(),
           Cookie :: cookie(),
           CryptoOpts :: crypto_opts().

%% Automatically infers Rails version from the cookie format, then verifies and
%% decrypts the cookie
verify_and_decrypt(auto, RailsKey, Cookie, Properties) ->
  RailsVersion = infer_rails_version(Cookie),
  verify_and_decrypt(RailsVersion, RailsKey, Cookie, Properties);

verify_and_decrypt(unknown, _RailsKey, _Cookie, _Properties) ->
  erlang:error(unknown_rails_version);

verify_and_decrypt(RailsVersion, RailsKey, Cookie, Properties) ->
  case verify(RailsVersion, RailsKey, Cookie, Properties) of
    {ok, CookieData} ->
      decrypt(RailsVersion, RailsKey, CookieData, Properties);
    Reason ->
      erlang:error(Reason)
  end.

-spec verify_and_decrypt(CookieFormat, SecretKeyBase, Cookie) -> decrypt_result()
      when CookieFormat :: rails_version() | auto,
           SecretKeyBase :: secret_key_base(),
           Cookie :: cookie().

verify_and_decrypt(RailsVersion, RailsKey, Cookie) ->
  verify_and_decrypt(RailsVersion, RailsKey, Cookie, []).

%%% PRIVATE FUNCTIONS

get_encrypted_cookie_salt(Properties) ->
  proplists:get_value(encrypted_cookie_salt, Properties).

get_encrypted_signed_cookie_salt(Properties) ->
  proplists:get_value(encrypted_signed_cookie_salt, Properties).

get_authenticated_encrypted_cookie_salt(Properties) ->
  proplists:get_value(authenticated_encrypted_cookie_salt, Properties).

get_cipher_alg(Properties) ->
  proplists:get_value(cipher_alg, Properties).

get_hmac_hash_alg(Properties) ->
  proplists:get_value(hmac_hash_alg, Properties).

get_pbkdf2_key(Secret, Salt, DerivedKeyLength) ->
  Iterations = 1000,
  {ok, Key} = pbkdf2:pbkdf2(sha, Secret, Salt, Iterations, DerivedKeyLength),
  Key.

%% This implementation is based on http_uri:decode(), because there is
%% no direct alternative in the recommended uri_string module.
%% cf. http://erlang.org/pipermail/erlang-questions/2020-March/099207.html
%% @private
uri_decode(String) when is_binary(String) ->
    do_decode_binary(String).

do_decode_binary(<<$%, Hex:2/binary, Rest/bits>>) ->
    <<(binary_to_integer(Hex, 16)), (do_decode_binary(Rest))/binary>>;
do_decode_binary(<<First:1/binary, Rest/bits>>) ->
    <<First/binary, (do_decode_binary(Rest))/binary>>;
do_decode_binary(<<>>) ->
    <<>>.
