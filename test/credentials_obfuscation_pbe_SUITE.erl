%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2019-2020 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(credentials_obfuscation_pbe_SUITE).
-include_lib("common_test/include/ct.hrl").
-compile(export_all).

%% This cipher is listed as supported on macOS, but doesn't actually work.
%% OTP bug: https://bugs.erlang.org/browse/ERL-1478
-define(SKIPPED_CIPHERS, [aes_ige256]).

all() -> [
    encrypt_decrypt,
    encrypt_decrypt_charlist_value,
    encrypt_decrypt_term
].

encrypt_decrypt(_Config) ->
    %% Take all available block ciphers.
    Hashes = credentials_obfuscation_pbe:supported_hashes(),
    Ciphers = credentials_obfuscation_pbe:supported_ciphers() -- ?SKIPPED_CIPHERS,
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


encrypt_decrypt_charlist_value(_Config) ->
    Hashes = credentials_obfuscation_pbe:supported_hashes(),
    Ciphers = credentials_obfuscation_pbe:supported_ciphers() -- ?SKIPPED_CIPHERS,
    _ = [begin
             Secret = crypto:strong_rand_bytes(16),
             Iterations = rand:uniform(100),
             Data = crypto:strong_rand_bytes(64),
             [begin
                  Expected = binary:part(Data, 0, Len),
                  Enc = credentials_obfuscation_pbe:encrypt(C, H, Iterations, Secret, binary_to_list(Expected)),
                  Expected = iolist_to_binary(credentials_obfuscation_pbe:decrypt(C, H, Iterations, Secret, Enc))
              end || Len <- lists:seq(0, byte_size(Data))]
         end || H <- Hashes, C <- Ciphers],
    ok.

encrypt_decrypt_term(_Config) ->
    %% Take all available block ciphers.
    Hashes = credentials_obfuscation_pbe:supported_hashes(),
    Ciphers = credentials_obfuscation_pbe:supported_ciphers() -- ?SKIPPED_CIPHERS,
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

