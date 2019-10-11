%%% Rails cookie utilities

-module(rails_cook).
-export([
  verify_cookie/4,
  decrypt_cookie/4,
  verify_and_decrypt_cookie/3,
  verify_and_decrypt_cookie/4
]).

%%% PUBLIC API

%% Since 5.1.0, Rails is leveraging AEAD (AES-256-GCM cipher) for faster
%% encryption/decryption and verification, in a single step.
%%
%% <cookie-payload> ::= <cipher-text> "--" <cipher-iv> "--" <cipher-auth-tag>
decrypt_cookie('rails-5.1', RailsKey, Cookie, Properties) ->
  [B64Ciphertext, B64IV, B64AuthTag] = binary:split(http_uri:decode(Cookie), <<"--">>),
  Ciphertext = base64:decode(B64Ciphertext),
  IV = base64:decode(B64IV),
  AuthTag = base64:decode(B64AuthTag),
  EncCookieKey = get_pbkdf2_key(RailsKey, <<"authenticated encrypted cookie">>, 32),
  CipherAlg = case get_cipher_alg(Properties) of
    undefined -> aes_gcm;
    Alg -> Alg
  end,
  crypto:block_decrypt(CipherAlg, EncCookieKey, IV, {Ciphertext, AuthTag});

%% Since Rails 4.0, the cookie data is base64 encoded and is a PAYLOAD--IV pair,
%% where payload is encrypted with AES-256-CBC block cipher.
%%
%% <verified-payload> ::= <cipher-text> "--" <cipher-iv>
decrypt_cookie('rails-4', RailsKey, Cookie, Properties) ->
  [B64Ciphertext, B64IV] = binary:split(http_uri:decode(Cookie), <<"--">>),
  Ciphertext = base64:decode(B64Ciphertext),
  IV = base64:decode(B64IV),
  EncCookieKey = get_pbkdf2_key(RailsKey, <<"encrypted cookie">>, 32),
  CipherAlg = case get_cipher_alg(Properties) of
    undefined -> aes_cbc256;
    Alg -> Alg
  end,
  crypto:block_decrypt(CipherAlg, EncCookieKey, IV, Ciphertext).

%% For Rails >= 5.1.0 A "null verifier" is used, i.e. no verification is done by
%% hand, as it is handled by the cipher. The payload is base64 encoded.
verify_cookie('rails-5.1', _RailsKey, Cookie, _Properties) ->
  {ok, base64:decode(Cookie)};

%% Rails < 5.1.0 uses a HMAC to prove the authenticity of a cookie payload
%%
%% <cookie-payload> ::= <verified-payload-b64> "--" <hmac>
verify_cookie('rails-4', RailsKey, Cookie, Properties) ->
  %% Rails 4 cookie is HMAC-signed at the outmost layer: PAYLOAD--SIGNATURE
  [CookieData, Digest] = binary:split(http_uri:decode(Cookie), <<"--">>),
  %% Verify that the signature is correct
  SigEncCookieKey = get_pbkdf2_key(RailsKey, <<"signed encrypted cookie">>, 64),
  HmacHashAlg = case get_hmac_hash_alg(Properties) of
    undefined -> sha;
    Alg -> Alg
  end,
  <<Hmac:160/integer>> = crypto:hmac(HmacHashAlg, SigEncCookieKey, CookieData),
  HexHmac = list_to_binary(lists:flatten(io_lib:format("~40.16.0b", [Hmac]))),
  if
    HexHmac =:= Digest -> % signature OK
      {ok, base64:decode(CookieData)};
    HexHmac =/= Digest -> % invalid signature
      bad_sig
  end.

verify_and_decrypt_cookie(RailsVersion, RailsKey, Cookie) ->
  verify_and_decrypt_cookie(RailsVersion, RailsKey, Cookie, []).

verify_and_decrypt_cookie(RailsVersion, RailsKey, Cookie, Properties) ->
  case verify_cookie(RailsVersion, RailsKey, Cookie, Properties) of
    {ok, CookieData} ->
      decrypt_cookie(RailsVersion, RailsKey, CookieData, Properties);
    Reason ->
      erlang:error(Reason)
  end.

%%% PRIVATE FUNCTIONS

get_cipher_alg(Properties) ->
  proplists:get_value('cipher-alg', Properties).

get_hmac_hash_alg(Properties) ->
  proplists:get_value('hmac-hash-alg', Properties).

get_pbkdf2_key(Secret, Salt, DerivedKeyLength) ->
  Iterations = 1000,
  {ok, Key} = pbkdf2:pbkdf2(sha, Secret, Salt, Iterations, DerivedKeyLength),
  Key.
