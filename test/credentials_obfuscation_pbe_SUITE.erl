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

-module(credentials_obfuscation_pbe_SUITE).
-include_lib("common_test/include/ct.hrl").
-compile(export_all).
 
all() -> [encrypt_decrypt, encrypt_decrypt_term].
 
encrypt_decrypt(_Config) ->
    %% Take all available block ciphers.
    Hashes = credentials_obfuscation_pbe:supported_hashes(),
    Ciphers = credentials_obfuscation_pbe:supported_ciphers(),
    %% For each cipher, try to encrypt and decrypt data sizes from 0 to 64 bytes
    %% with a random Secret.
    _ = [begin
             Secret = crypto:strong_rand_bytes(16),
             Iterations = rand:uniform(100),
             Data = crypto:strong_rand_bytes(64),
             [begin
                  Expected = binary:part(Data, 0, Len),
                  Enc = credentials_obfuscation_pbe:encrypt(C, H, Iterations, Secret, Expected),
                  Expected = iolist_to_binary(credentials_obfuscation_pbe:decrypt(C, H, Iterations, Secret, Enc))
              end || Len <- lists:seq(0, byte_size(Data))]
         end || H <- Hashes, C <- Ciphers],
    ok.

encrypt_decrypt_term(_Config) ->
    %% Take all available block ciphers.
    Hashes = credentials_obfuscation_pbe:supported_hashes(),
    Ciphers = credentials_obfuscation_pbe:supported_ciphers(),
    %% Different Erlang terms to try encrypting.
    DataSet = [
        10000,
        [5672],
        [{"127.0.0.1", 5672},
            {"::1",       5672}],
        [{connection, info}, {channel, info}],
        [{cacertfile,           "/path/to/testca/cacert.pem"},
            {certfile,             "/path/to/server/cert.pem"},
            {keyfile,              "/path/to/server/key.pem"},
            {verify,               verify_peer},
            {fail_if_no_peer_cert, false}],
        [<<".*">>, <<".*">>, <<".*">>]
    ],
    _ = [begin
             Secret = crypto:strong_rand_bytes(16),
             Iterations = rand:uniform(100),
             Enc = credentials_obfuscation_pbe:encrypt_term(C, H, Iterations, Secret, Data),
             Data = credentials_obfuscation_pbe:decrypt_term(C, H, Iterations, Secret, Enc)
         end || H <- Hashes, C <- Ciphers, Data <- DataSet],
    ok.
 
