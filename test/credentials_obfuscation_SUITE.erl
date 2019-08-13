-module(credentials_obfuscation_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).
 
all() -> [encrypt_decrypt].
 
encrypt_decrypt(_Config) ->
    application:ensure_all_started(credentials_obfuscation),
    Credentials = <<"guest">>,
    Encrypted = credentials_obfuscation:encrypt(Credentials),
    Credentials = credentials_obfuscation:decrypt(Encrypted),
    ok.
 