-module(rails_cook_tests).

-include_lib("eunit/include/eunit.hrl").
-include("rails_cook.hrl").

rails_cook_test_() ->
  {foreach, fun setup/0, fun teardown/1,
    [{with, [T]} || T <- [
      fun test_rails4_infer/1,
      fun test_rails51_infer/1,
      fun test_unknown_infer/1,
      fun test_verify_unknown/1,
      fun test_verify_rails4/1,
      fun test_verify_rails51/1,
      fun test_decrypt_unknown/1,
      fun test_decrypt_rails4/1,
      fun test_decrypt_rails5/1,
      fun test_verify_and_decrypt_rails4/1,
      fun test_verify_and_decrypt_rails51/1,
      fun test_verify_and_decrypt_rails51_salt_changed/1,
      fun test_verify_and_decrypt_rails51_cipher_aes192gcm/1]]}.

setup() ->
    % Uncomment to run tests with dbg:
    % dbg:tracer(),
    % dbg:p(all, call),
    % dbg:tpl(rails_cook, []),
    rails_cook.

teardown(_Module) -> ok.

-define(RAILS4_SECRET_BASE,
  <<"3431bc53c9a48f5ad58a0ba268bfc3b27e50847fc09a57128c81618b91a0de310a2fb725c8"
  "24deab3ba802642a1465235cfce9f194596fec15c2cad4ddae7353">>
).
-define(RAILS4_COOKIE_DEFAULT,
  <<"cSsvQWJKcHo2UUJ3TjZObmNyWlNxK0IyRU9OeDhTNVk0RWFrZmJ4SEFuM0w3cTI1RnlYbEZXeX"
  "NVMk9tMXorMVcvbjd6a3oydEdwZktmV2t4K1NXb2xTcWZQUEdNR1hBalM0QitBZmRJYzZkSlE3UD"
  "QxSERpeFhudGdMbXJ0WWxrSTIyYkxGNUhodmNvcWZnOFRJcWkvL1NPOFdSVThacytMZ1JlMElzVU"
  "F2TUF5VWZoYXVRZ3QyYk9udWxzTXkxUzF6cUF1NEhoRytLSlJXajc1bi9UdDF4OEgzbk1rTkR0b2"
  "tlaFFnUjlhTT0tLUVDZElxY0tTcWdHN0hMUXd1UlZ0N2c9PQ%3D%3D--5d0db878511fa0375932"
  "e23a4a19b6d6dcff5323">>
).
-define(RAILS4_COOKIE_ENCRYPTED_PAYLOAD,
  <<"q+/AbJpz6QBwN6NncrZSq+B2EONx8S5Y4EakfbxHAn3L7q25FyXlFWysU2Om1z+1W/n7zkz2tG"
  "pfKfWkx+SWolSqfPPGMGXAjS4B+AfdIc6dJQ7P41HDixXntgLmrtYlkI22bLF5Hhvcoqfg8TIqi/"
  "/SO8WRU8Zs+LgRe0IsUAvMAyUfhauQgt2bOnulsMy1S1zqAu4HhG+KJRWj75n/Tt1x8H3nMkNDto"
  "kehQgR9aM=--ECdIqcKSqgG7HLQwuRVt7g==">>
).
-define(RAILS4_COOKIE_DEFAULT_PLAINTEXT,
  <<"{\"session_id\":\"54997d3aca182c04b4c3dccb0f5d245a\",\"warden.user.user.ke"
  "y\":[[17],\"$2a$04$pX8h2AAPucIQ7ClnIiAdLe\"],\"_csrf_token\":\"j44q9drLtA4vq"
  "5z8+jhF35zBsTypbGWHVagGTRRMLdE=\"}">>
).

-define(RAILS5_SECRET_BASE,
  <<"e7e4eb74a5f53c851a3fa26561b882ab4b762567ebd67804f4feaf1bef1cd5bef2b00bf811"
  "10dcf36e965215472fe4bdf8b49149b6b6471f4e0f6f2cd2b58602">>
).
-define(RAILS5_COOKIE_DEFAULT,
  <<"Ym9OcjbK0D6fr%2B9GqKvzSknLPv8yPE%2Fa%2Fj9%2FYquApL8IuUlWeuKqYbB4P6i5mguQ93"
  "GxPtXx%2BsGasEkZlywdL6BPo9tW9UapoD5Ok%2F%2BKbm46gM9HRg%2FM7bj0YIyhSNJznU%2Fy"
  "7SXvWlcRtTEToOSPFA9e%2BTgVzFzHvJ744YW%2FOlnU5%2BrDds5vK4xFNcG6FfGUCOwoGrbDDp"
  "KjOpb3EJCoMtX%2FqKOnTpSfrE0n9bRyqQOOf694iodOF56l6eAzZP%2FZtVzBNsJRxD52igCiv9"
  "SYL1CfINm%2BXqMBJn5W%2FmBJKj0mO%2BDFpO711xmDGnItbgaY5X80QUL8qQK8Kbsfl80pyijS"
  "CvJuyXp9Tou%2BWAkSR9VZPhhexfpx2G0cOQ27%2B0ttdlCuOK8E3BcUeMQlgA8pWSqoT6m1ENUH"
  "Og%3D%3D--CkhHK5nHNHVWnWw4--XE%2BFWYSbox8iQI2gbEWnrA%3D%3D">>
).
-define(RAILS5_COOKIE_DEFAULT_PLAINTEXT,
  <<"{\"_rails\":{\"message\":\"eyJzZXNzaW9uX2lkIjoiMjBkZGYyY2U0ZGYyZDI2MTkyMDh"
  "hNDQ3ZDQ4MWFmNDUiLCJ3YXJkZW4udXNlci51c2VyLmtleSI6W1sxXSwiJDJhJDEyJDliaURzY2x"
  "hbjd5Wk43SFdxM2FJWGUiXSwiZmxhc2giOnsiZGlzY2FyZCI6W10sImZsYXNoZXMiOnsibm90aWN"
  "lIjoiU2lnbmVkIGluIHN1Y2Nlc3NmdWxseS4ifX19\",\"exp\":null,\"pur\":\"cookie._t"
  "esty_railsy_session\"}}">>
).
-define(RAILS5_COOKIE_SALT,
  <<"g2fbs3FHPPQhFlqgiM3eK2g2XpKZSWqNnx7h2IxT6%2Fg0NjS7RQPMgyHoIoP%2B1nF%2FlxlN"
  "xsQVuSF912HQtkFEM2jCld7ltjkg8k%2FxPAsNzcNfWAJ9q5%2FnpQO%2BrldusWlvp43G%2FVPZ"
  "8WyUDE%2FVdJIQvGfa%2BJf%2Fk7HIVg%2B9%2FC3%2BDtbSksEQ%2FmrND3y6VBW0jvjKfEzf9x"
  "1mzSFFcV4NQSiJdmpi6J2yAUXek22mv7x3PIEDv%2BYouI%2Fws1JbMmKIXDXWVuvrjYNwSby6Mf"
  "v3VJFq12ms%2FC02v61KTglCJs6dvr%2BFYLau1LgErF9qJ8Q%2FR2aBij6EPfZAHQaQZ9fOMusw"
  "1Xy%2BSPXYa%2F6BGk2gFRz7ra3Gx3jU8LYczUaddjytmaIYHWHGW%2FMPj0VkYxeE06JJCu%2Bf"
  "62eWQPUyXg%3D%3D--x9mMJjLrWdekMoXx--XqaS3xAztPWibBbW30NMnw%3D%3D">>
).
-define(RAILS5_COOKIE_SALT_PLAINTEXT,
  <<"{\"_rails\":{\"message\":\"eyJzZXNzaW9uX2lkIjoiYTRjMjIyYTQ0MGJlZGMzNjlkNzN"
  "kODNhOWZiMGQzZDIiLCJ3YXJkZW4udXNlci51c2VyLmtleSI6W1sxXSwiJDJhJDEyJDliaURzY2x"
  "hbjd5Wk43SFdxM2FJWGUiXSwiZmxhc2giOnsiZGlzY2FyZCI6W10sImZsYXNoZXMiOnsibm90aWN"
  "lIjoiU2lnbmVkIGluIHN1Y2Nlc3NmdWxseS4ifX19\",\"exp\":null,\"pur\":\"cookie._t"
  "esty_railsy_session\"}}">>
).
-define(RAILS5_COOKIE_AES192GCM,
  <<"PcDbAf9Nq1mMn%2Bw8YeD8rXGDi9mQTVegAHruS2QJsgiqd%2BqF5YyB3CmlQg%2B6sN36lf2d"
  "3fWX%2Fjd%2FbXvlfBYaBExy1Yua%2BQh9Sc89lKtZ5flxx%2BvQ6ylHCDK1IWT%2BeE71kCe6er"
  "jmmrJ3ZvO1ckU1LaZ2spCIUrGa%2BNUrgVp3iT0IH5aue6uwsCahcJmRBgHWLe82jTVy%2BLazlp"
  "VzNc0%2FxY98wnjisjiPDgmoebJkb%2FRX1UGoA1DHwsMgV1yPn6EX8HgW%2BMN6GE%2F6llXDAn"
  "nPoM8%2BS4%2BpPsi6%2FMp4uZGEQvKH4gv59RlO5qdmkl9jN7RQl%2B2Q0BJtCOz5U1z8rxM%2F"
  "Wte0I%2BOGKTq13bkMHCmxziyYt5QHRqGcvm9eVBMsOvyoXjNBME7%2BJerE17tRsD4BSCbwV7tz"
  "TkosxQ%3D%3D--t%2BHbujcf4Xx64I9B--Lfqo%2FsZqBTApqgQMjvd9AQ%3D%3D">>
).
-define(RAILS5_COOKIE_AES192GCM_PLAINTEXT,
  <<"{\"_rails\":{\"message\":\"eyJzZXNzaW9uX2lkIjoiNDU2N2JmYjY5YzFkNDQ2YWRjODk"
  "wZmNjZjU5Y2VlMzIiLCJ3YXJkZW4udXNlci51c2VyLmtleSI6W1sxXSwiJDJhJDEyJDliaURzY2x"
  "hbjd5Wk43SFdxM2FJWGUiXSwiZmxhc2giOnsiZGlzY2FyZCI6W10sImZsYXNoZXMiOnsibm90aWN"
  "lIjoiU2lnbmVkIGluIHN1Y2Nlc3NmdWxseS4ifX19\",\"exp\":null,\"pur\":\"cookie._t"
  "esty_railsy_session\"}}">>
).

test_rails4_infer(Mod) ->
  Version = Mod:infer_rails_version(?RAILS4_COOKIE_DEFAULT),
  ?assertEqual(rails_4, Version, "Correctly detects cookie format as Rails 4").

test_rails51_infer(Mod) ->
  Version = Mod:infer_rails_version(?RAILS5_COOKIE_DEFAULT),
  ?assertEqual(rails_5_1, Version,
    "Correctly detects cookie format as Rails 5.1").

test_unknown_infer(Mod) ->
  Version = Mod:infer_rails_version(<<"Not known">>),
  ?assertEqual(unknown, Version, "Infers unknown if not a recognized format").

test_verify_unknown(Mod) ->
  ?assertError(unknown_rails_version,
    Mod:verify(unknown, <<"secret key base">>, <<"cookie">>),
    "Cannot verify a cookie for an unknown Rails version").

test_verify_rails4(Mod) ->
  ?assertEqual({ok, ?RAILS4_COOKIE_ENCRYPTED_PAYLOAD},
    Mod:verify(rails_4, ?RAILS4_SECRET_BASE, ?RAILS4_COOKIE_DEFAULT),
    "Correctly verifies a Rails 4 session cookie").

test_verify_rails51(Mod) ->
  Cookie = <<"can be whatever">>,
  ?assertEqual({ok, Cookie},
    Mod:verify(rails_5_1, <<"secret key base">>, Cookie),
    "Rails 5.1 uses a null verifier").

test_decrypt_unknown(Mod) ->
  ?assertError(unknown_rails_version,
    Mod:decrypt(unknown, <<"secret key base">>, <<"cookie">>),
    "Cannot decrypt a cookie for an unknown Rails version").

test_decrypt_rails4(Mod) ->
  {CookieFormat, Result} = Mod:decrypt(rails_4, ?RAILS4_SECRET_BASE,
    ?RAILS4_COOKIE_ENCRYPTED_PAYLOAD),
  ?assertEqual(rails_4, CookieFormat,
    "Correctly detects cookie format as Rails 4"),
  ?assertEqual(?RAILS4_COOKIE_DEFAULT_PLAINTEXT, Result,
    "Correctly decrypts a Rails 4 session cookie after validation").

test_decrypt_rails5(Mod) ->
  {CookieFormat, Result} = Mod:decrypt(rails_5_1, ?RAILS5_SECRET_BASE,
    ?RAILS5_COOKIE_DEFAULT),
  ?assertEqual(rails_5_1, CookieFormat,
    "Correctly detects cookie format as Rails 5.1"),
  ?assertEqual(?RAILS5_COOKIE_DEFAULT_PLAINTEXT, Result,
    "Correctly decrypts a Rails 5.1 session cookie").

test_verify_and_decrypt_rails4(Mod) ->
  {CookieFormat, Result} = Mod:verify_and_decrypt(
    auto, ?RAILS4_SECRET_BASE, ?RAILS4_COOKIE_DEFAULT),
  ?assertEqual(rails_4, CookieFormat,
    "Correctly detects cookie format as Rails 4"),
  ?assertEqual(?RAILS4_COOKIE_DEFAULT_PLAINTEXT, Result,
    "Correctly verifies and decrypts a Rails 4 session with the valid base").

test_verify_and_decrypt_rails51(Mod) ->
  {CookieFormat, Result} = Mod:verify_and_decrypt(
    auto, ?RAILS5_SECRET_BASE, ?RAILS5_COOKIE_DEFAULT),
  ?assertEqual(rails_5_1, CookieFormat,
    "Correctly detects cookie format as Rails 5.1"),
  ?assertEqual(?RAILS5_COOKIE_DEFAULT_PLAINTEXT, Result,
    "Correctly verifies and decrypts a Rails 5.1 session with the valid base"),

  ?assertError(bad_sig,
    Mod:verify_and_decrypt(auto, <<"bad secret base">>, ?RAILS5_COOKIE_DEFAULT),
    "Errors if using incorrect secret key base").

test_verify_and_decrypt_rails51_salt_changed(Mod) ->
  {CookieFormat, Result} = Mod:verify_and_decrypt(
    auto, ?RAILS5_SECRET_BASE, ?RAILS5_COOKIE_SALT,
    [{authenticated_encrypted_cookie_salt, <<"other salt">>}]),
  ?assertEqual(rails_5_1, CookieFormat,
    "Correctly detects cookie format as Rails 5.1"),
  ?assertEqual(?RAILS5_COOKIE_SALT_PLAINTEXT, Result,
    "Correctly verifies and decrypts a Rails 5.1 session with custom salt").

test_verify_and_decrypt_rails51_cipher_aes192gcm(Mod) ->
  {CookieFormat, Result} = Mod:verify_and_decrypt(
    auto, ?RAILS5_SECRET_BASE, ?RAILS5_COOKIE_AES192GCM,
    [{cipher_alg, aes_192_gcm}]),
  ?assertEqual(rails_5_1, CookieFormat,
    "Correctly detects cookie format as Rails 5.1"),
  ?assertEqual(?RAILS5_COOKIE_AES192GCM_PLAINTEXT, Result,
    "Correctly verifies and decrypts a Rails 5.1 session with a different cipher").
