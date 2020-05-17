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

-module(credentials_obfuscation_app).

-behaviour(application).

-export([start/2, stop/1]).

%% Dummy supervisor - see Ulf Wiger's comment at
%% http://erlang.2086793.n4.nabble.com/initializing-library-applications-without-processes-td2094473.html
-behaviour(supervisor).
-export([init/1]).

-export([enabled/0, secret/0, cipher/0, hash/0, iterations/0]).

start(_StartType, _StartArgs) ->
    ok = case enabled() of
             true ->
                 Secret = get_secret(),
                 T = ets:new(table_name(), [set, public, named_table]),
                 ets:insert_new(T, {secret, Secret}),
                 %% cipher/decipher attempt to crash now instead of at some awkward moment
                 check();
             false ->
                 ok
         end,
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

check() ->
    Value = <<"dummy">>,
    Encrypted = credentials_obfuscation:encrypt(Value),
    Value = credentials_obfuscation:decrypt(Encrypted),
    ok.

stop(_State) ->
    ok.

init([]) ->
    {ok, {{one_for_one, 1, 5}, []}}.

enabled() ->
    application:get_env(credentials_obfuscation, enabled, true).

secret() ->
    maybe_update_secret(ets:lookup(table_name(), secret)).

table_name() ->
    application:get_env(credentials_obfuscation, ets_table_name, credentials_obfuscation).

cipher() ->
    application:get_env(credentials_obfuscation, cipher, credentials_obfuscation_pbe:default_cipher()).

hash() ->
    application:get_env(credentials_obfuscation, hash, credentials_obfuscation_pbe:default_hash()).

iterations() ->
    application:get_env(credentials_obfuscation, iterations, credentials_obfuscation_pbe:default_iterations()).

maybe_update_secret([{secret, '$pending-secret'=Pending}]) ->
    case get_secret() of
        Pending ->
            Pending;
        UpdatedSecret ->
            ets:insert(table_name(), {secret, UpdatedSecret}),
            UpdatedSecret
    end;
maybe_update_secret([{secret, Secret}]) ->
    Secret.

get_secret() ->
    case application:get_env(credentials_obfuscation, secret) of
        {ok, cookie} ->
            case erlang:get_cookie() of
                nocookie ->
                    '$pending-secret';
                Cookie ->
                    atom_to_binary(Cookie)
            end;
        {ok, PredefinedSecret} when is_binary(PredefinedSecret) ->
            PredefinedSecret;
        undefined ->
            crypto:strong_rand_bytes(128)
    end.
