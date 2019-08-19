%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License at
%% https://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
%% License for the specific language governing rights and limitations
%% under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is GoPivotal, Inc.
%% Copyright (c) 2019 Pivotal Software, Inc.  All rights reserved.
%%

-module(credentials_obfuscation_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).
 
all() -> [encrypt_decrypt, change_default_cipher, disabled, application_failure_for_invalid_cipher].

init_per_testcase(disabled, Config) ->
    application:set_env(credentials_obfuscation, enabled, false),
    application:ensure_all_started(credentials_obfuscation),
    Config;
init_per_testcase(change_default_cipher, Config) ->
    %% use weak cipher, to avoid collision with defaults
    %% defaults should only grow stronger
    application:set_env(credentials_obfuscation, cipher, aes_128_cbc),
    application:set_env(credentials_obfuscation, hash, sha256),
    application:set_env(credentials_obfuscation, iterations, 100),
    application:ensure_all_started(credentials_obfuscation),
    Config;
init_per_testcase(application_failure_for_invalid_cipher, Config) ->
    application:set_env(credentials_obfuscation, cipher, dummy_cipher),
    Config;
init_per_testcase(_TestCase, Config) ->
    application:ensure_all_started(credentials_obfuscation),
    Config.

end_per_testcase(_TestCase, Config) ->
    application:stop(credentials_obfuscation),
    [application:unset_env(credentials_obfuscation, Key) || {Key, _} <- application:get_all_env(credentials_obfuscation)],
    Config.
 
encrypt_decrypt(_Config) ->
    Credentials = <<"guest">>,
    Encrypted = credentials_obfuscation:encrypt(Credentials),
    ?assertNotEqual(Credentials, Encrypted),
    ?assertEqual(Credentials, credentials_obfuscation:decrypt(Encrypted)),
    ok.

change_default_cipher(_Config) ->
    ?assertNotEqual(credentials_obfuscation_pbe:default_cipher(), credentials_obfuscation_app:cipher()),
    ?assertNotEqual(credentials_obfuscation_pbe:default_hash(), credentials_obfuscation_app:hash()),
    ?assertNotEqual(credentials_obfuscation_pbe:default_iterations(), credentials_obfuscation_app:iterations()),
    Credentials = <<"guest">>,
    Encrypted = credentials_obfuscation:encrypt(Credentials),
    ?assertNotEqual(Credentials, Encrypted),
    ?assertEqual(Credentials, credentials_obfuscation:decrypt(Encrypted)),
    ok.

disabled(_Config) ->
    ?assertNot(credentials_obfuscation_app:enabled()),
    Credentials = <<"guest">>,
    ?assertEqual(Credentials, credentials_obfuscation:encrypt(Credentials)),
    ?assertEqual(Credentials, credentials_obfuscation:decrypt(Credentials)),
    ok.

application_failure_for_invalid_cipher(_Config) ->
    {error, _ } = application:ensure_all_started(credentials_obfuscation),
    ok.