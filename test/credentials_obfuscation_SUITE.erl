%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2019-2020 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(credentials_obfuscation_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() -> [encrypt_decrypt,
          encrypt_decrypt_char_list_value,
          use_predefined_secret,
          use_cookie_as_secret,
          encryption_happens_only_when_secret_available,
          change_default_cipher,
          disabled,
          refresh_configuration,
          application_failure_for_invalid_cipher].

init_per_testcase(disabled, Config) ->
    ok = application:set_env(credentials_obfuscation, enabled, false),
    {ok, _} = application:ensure_all_started(credentials_obfuscation),
    Config;
init_per_testcase(refresh_configuration, Config) ->
    ok = application:set_env(credentials_obfuscation, enabled, true),
    {ok, _} = application:ensure_all_started(credentials_obfuscation),
    Config;
init_per_testcase(use_predefined_secret, Config) ->
    ok = application:set_env(credentials_obfuscation, secret, <<"credentials-obfuscation#2">>),
    {ok, _} = application:ensure_all_started(credentials_obfuscation),
    Config;
init_per_testcase(use_cookie_as_secret, Config) ->
    ok = application:set_env(credentials_obfuscation, secret, cookie),
    Config;
init_per_testcase(encryption_happens_only_when_secret_available, Config) ->
    ok = application:set_env(credentials_obfuscation, enabled, true),
    Config;
init_per_testcase(change_default_cipher, Config) ->
    ok = application:set_env(credentials_obfuscation, cipher, aes_256_cbc),
    ok = application:set_env(credentials_obfuscation, hash, sha512),
    ok = application:set_env(credentials_obfuscation, iterations, 100),
    {ok, _} = application:ensure_all_started(credentials_obfuscation),
    Config;
init_per_testcase(application_failure_for_invalid_cipher, Config) ->
    ok = application:set_env(credentials_obfuscation, cipher, dummy_cipher),
    Config;
init_per_testcase(_TestCase, Config) ->
    {ok, _} = application:ensure_all_started(credentials_obfuscation),
    Secret = crypto:strong_rand_bytes(128),
    ok = credentials_obfuscation:set_secret(Secret),
    Config.

end_per_testcase(_TestCase, Config) ->
    case application:stop(credentials_obfuscation) of
        ok ->
            ok;
        {error, {not_started, credentials_obfuscation}} ->
            ok
    end,
    [ok = application:unset_env(credentials_obfuscation, Key) || {Key, _} <- application:get_all_env(credentials_obfuscation)],
    Config.

encrypt_decrypt(_Config) ->
    Credentials = <<"guest">>,
    Encrypted = credentials_obfuscation:encrypt(Credentials),
    ?assertNotEqual(Credentials, Encrypted),
    ?assertEqual(Credentials, credentials_obfuscation:decrypt(Encrypted)),
    ok.

encrypt_decrypt_char_list_value(_Config) ->
    Credentials = "guest",
    Expected = <<"guest">>,
    Encrypted = credentials_obfuscation:encrypt(Credentials),
    ?assertNotEqual(Expected, Encrypted),
    ?assertEqual(Expected, credentials_obfuscation:decrypt(Encrypted)),
    ok.

use_predefined_secret(_Config) ->
    Secret = crypto:strong_rand_bytes(128),
    ok = credentials_obfuscation:set_secret(Secret),
    ?assertEqual(Secret, credentials_obfuscation:secret()),
    ok.

use_cookie_as_secret(_Config) ->
    _ = net_kernel:stop(),
    ?assertEqual(nocookie, erlang:get_cookie()),

    %% Start epmd
    os:cmd("epmd -daemon"),

    {ok, _} = net_kernel:start(['use_cookie_as_secret@localhost']),
    Cookie = erlang:get_cookie(),
    ?assertNotEqual(nocookie, Cookie),
    {ok, _} = application:ensure_all_started(credentials_obfuscation),
    CookieBin = atom_to_binary(Cookie, utf8),
    ok = credentials_obfuscation:set_secret(CookieBin),
    ?assertEqual(CookieBin, credentials_obfuscation:secret()),
    ok = net_kernel:stop(),
    ok.

encryption_happens_only_when_secret_available(_Config) ->
    _ = net_kernel:stop(),
    Uri = <<"amqp://super:secret@localhost:5672">>,
    {ok, _} = application:ensure_all_started(credentials_obfuscation),

    ?assertEqual(nocookie, erlang:get_cookie()),

    ?assert(credentials_obfuscation:enabled()),
    ?assertEqual('$pending-secret', credentials_obfuscation:secret()),

    NotReallyEncryptedUri = credentials_obfuscation:encrypt(Uri),
    ?assertEqual({plaintext, Uri}, NotReallyEncryptedUri),
    ?assertEqual(Uri, credentials_obfuscation:decrypt(NotReallyEncryptedUri)),

    %% Start epmd
    os:cmd("epmd -daemon"),

    % start up disterl, which creates a cookie
    {ok, _} = net_kernel:start(['use_cookie_as_secret@localhost']),
    Cookie = erlang:get_cookie(),
    ?assertNotEqual(nocookie, Cookie),

    CookieBin = atom_to_binary(Cookie, utf8),
    ok = credentials_obfuscation:set_secret(CookieBin),
    ?assertEqual(CookieBin, credentials_obfuscation:secret()),

    EncryptedUri = credentials_obfuscation:encrypt(Uri),
    {encrypted, _} = EncryptedUri,
    ?assertEqual(Uri, credentials_obfuscation:decrypt(EncryptedUri)),

    ok = net_kernel:stop(),
    ok.

change_default_cipher(_Config) ->
    ?assertNotEqual(credentials_obfuscation_pbe:default_cipher(), credentials_obfuscation:cipher()),
    ?assertNotEqual(credentials_obfuscation_pbe:default_hash(), credentials_obfuscation:hash()),
    ?assertNotEqual(credentials_obfuscation_pbe:default_iterations(), credentials_obfuscation:iterations()),
    Credentials = <<"guest">>,
    Encrypted = credentials_obfuscation:encrypt(Credentials),
    ?assertNotEqual(Credentials, Encrypted),
    ?assertEqual(Credentials, credentials_obfuscation:decrypt(Encrypted)),
    ok.

disabled(_Config) ->
    ?assertNot(credentials_obfuscation:enabled()),
    Credentials = <<"guest">>,
    ?assertEqual(Credentials, credentials_obfuscation:encrypt(Credentials)),
    ?assertEqual(Credentials, credentials_obfuscation:decrypt(Credentials)),
    ok.

refresh_configuration(_Config) ->
    ?assert(credentials_obfuscation:enabled()),
    ok = application:set_env(credentials_obfuscation, enabled, false),
    ok = credentials_obfuscation:refresh_config(),
    ?assertNot(credentials_obfuscation:enabled()),
    Value = <<"foobarbazbat">>,
    ?assertEqual(Value, credentials_obfuscation:encrypt(Value)),
    ?assertEqual(Value, credentials_obfuscation:decrypt(Value)),
    ok.

application_failure_for_invalid_cipher(_Config) ->
    {error, _} = application:ensure_all_started(credentials_obfuscation),
    ok.
