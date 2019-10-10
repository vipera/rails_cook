%%% Rails cookie utilities

-module(rails_cook).
-export([
  verify_cookie/3,
  decrypt_cookie/3,
  verify_and_decrypt_cookie/3
]).

%%% PUBLIC API

decrypt_cookie(rails5, RailsKey, Cookie) ->
  %% the cookie data is base64 encoded and is a PAYLOAD--IV pair, where
  %% payload is encrypted with AES-256-CBC block cipher
  [Encrypted, B64IV] = binary:split(http_uri:decode(Cookie), <<"--">>),
  Ciphertext = base64:decode(Encrypted),
  IV = base64:decode(B64IV),
  EncCookieKey = get_pbkdf2_key(RailsKey, <<"encrypted cookie">>, 32),
  crypto:block_decrypt(aes_cbc256, EncCookieKey, IV, Ciphertext).

verify_cookie(rails5, RailsKey, Cookie) ->
  %% Rails5 cookie is HMAC-signed at the outmost layer: PAYLOAD--SIGNATURE
  [CookieData, Digest] = binary:split(http_uri:decode(Cookie), <<"--">>),
  %% Verify that the signature is correct
  SigEncCookieKey = get_pbkdf2_key(RailsKey, <<"signed encrypted cookie">>, 64),
  <<Hmac:160/integer>> = crypto:hmac(sha, SigEncCookieKey, CookieData),
  HexHmac = list_to_binary(lists:flatten(io_lib:format("~40.16.0b", [Hmac]))),
  if
    HexHmac =:= Digest -> % signature OK
      {ok, base64:decode(CookieData)};
    HexHmac =/= Digest -> % invalid signature
      bad_sig
  end.

verify_and_decrypt_cookie(rails5, RailsKey, Cookie) ->
  case verify_cookie(rails5, RailsKey, Cookie) of
    {ok, CookieData} ->
      decrypt_cookie(rails5, RailsKey, CookieData);
    Reason ->
      erlang:error(Reason)
  end.

%%% PRIVATE FUNCTIONS

get_pbkdf2_key(Secret, Salt, DerivedKeyLength) ->
  Iterations = 1000,
  {ok, Key} = pbkdf2:pbkdf2(sha, Secret, Salt, Iterations, DerivedKeyLength),
  Key.
