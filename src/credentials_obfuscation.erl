%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at https://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is GoPivotal, Inc.
%% Copyright (c) 2019 Pivotal Software, Inc.  All rights reserved.
%%

-module(credentials_obfuscation).

%% Configuration API
-export([enabled/0, cipher/0, hash/0, iterations/0, secret/0]).

%% API
-export([set_secret/1, encrypt/1, decrypt/1, refresh_config/0]).

-spec enabled() -> boolean().
enabled() ->
    credentials_obfuscation_svc:get_config(enabled).

-spec cipher() -> atom().
cipher() ->
    credentials_obfuscation_svc:get_config(cipher).

-spec hash() -> atom().
hash() ->
    credentials_obfuscation_svc:get_config(hash).

-spec iterations() -> non_neg_integer().
iterations() ->
    credentials_obfuscation_svc:get_config(iterations).

-spec secret() -> binary() | '$pending-secret'.
secret() ->
    credentials_obfuscation_svc:get_config(secret).

-spec set_secret(binary()) -> ok.
set_secret(Secret) when is_binary(Secret) ->
    ok = credentials_obfuscation_svc:set_secret(Secret).

-spec encrypt(term()) -> {plaintext, term()} | {encrypted, binary()}.
encrypt(none) -> none;
encrypt(undefined) -> undefined;
encrypt(Term) ->
    credentials_obfuscation_svc:encrypt(Term).

-spec decrypt({plaintext, term()} | {encrypted, binary()}) -> term().
decrypt(none) -> none;
decrypt(undefined) -> undefined;
decrypt(Term) ->
    credentials_obfuscation_svc:decrypt(Term).

-spec refresh_config() -> ok.
refresh_config() ->
    credentials_obfuscation_svc:refresh_config().
