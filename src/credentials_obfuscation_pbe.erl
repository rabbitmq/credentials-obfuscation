%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2019-2022 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(credentials_obfuscation_pbe).

-include("credentials_obfuscation.hrl").
-include("otp_crypto.hrl").

-export([supported_ciphers/0, supported_hashes/0, default_cipher/0, default_hash/0, default_iterations/0]).
-export([encrypt_term/5, decrypt_term/5]).
-export([encrypt/5, decrypt/5]).


%% Supported ciphers and hashes

%% We only support block ciphers that use an initialization vector.

%% AEAD ciphers expect Associated Data (AD), which we don't have. It would be
%% convenient if there was a way to get this list rather than hardcode it:
%% https://bugs.erlang.org/browse/ERL-1479.
-define(AEAD_CIPHERS, [aes_gcm, aes_ccm, chacha20_poly1305]).

supported_ciphers() ->
    SupportedByCrypto = crypto:supports(ciphers),
    lists:filter(fun(Cipher) ->
        Mode = maps:get(mode, crypto:cipher_info(Cipher)),
        not lists:member(Mode, [ccm_mode, ecb_mode, gcm_mode])
    end,
    SupportedByCrypto) -- ?AEAD_CIPHERS.

supported_hashes() ->
    crypto:supports(hashs).

%% Default encryption parameters.
default_cipher() ->
    aes_128_cbc.

default_hash() ->
    sha256.

default_iterations() ->
    1.

%% Encryption/decryption of arbitrary Erlang terms.

encrypt_term(_Cipher, _Hash, _Iterations, ?PENDING_SECRET, Term) ->
    {plaintext, Term};
encrypt_term(Cipher, Hash, Iterations, Secret, Term) ->
    encrypt(Cipher, Hash, Iterations, Secret, term_to_binary(Term)).

decrypt_term(_Cipher, _Hash, _Iterations, _Secret, {plaintext, Term}) ->
    Term;
decrypt_term(Cipher, Hash, Iterations, Secret, Base64Binary) ->
    binary_to_term(decrypt(Cipher, Hash, Iterations, Secret, Base64Binary)).

%% The cipher for encryption is from the list of supported ciphers.
%% The hash for generating the key from the secret is from the list
%% of supported hashes. See crypto:supports/0 to obtain both lists.
%% The key is generated by applying the hash N times with N >= 1.
%%
%% The encrypt/5 function returns a base64 binary and the decrypt/5
%% function accepts that same base64 binary.

-spec encrypt(cipher_iv(), hash_algorithm(),
              pos_integer(), iodata() | '$pending-secret', iodata()) -> {plaintext, binary()} | {encrypted, binary()}.
encrypt(_Cipher, _Hash, _Iterations, ?PENDING_SECRET, ClearText) ->
    {plaintext, iolist_to_binary(ClearText)};
encrypt(Cipher, Hash, Iterations, Secret, ClearText) when is_list(ClearText) ->
    encrypt(Cipher, Hash, Iterations, Secret, list_to_binary(ClearText));
encrypt(Cipher, Hash, Iterations, Secret, ClearText) when is_binary(ClearText) ->
    Salt = crypto:strong_rand_bytes(16),
    Ivec = crypto:strong_rand_bytes(iv_length(Cipher)),
    Key = make_key(Cipher, Hash, Iterations, Secret, Salt),
    Binary = crypto:crypto_one_time(Cipher, Key, Ivec, pad(Cipher, ClearText), true),
    Encrypted = base64:encode(<<Salt/binary, Ivec/binary, Binary/binary>>),
    {encrypted, Encrypted}.

-spec decrypt(cipher_iv(), hash_algorithm(),
              pos_integer(), iodata(), {'encrypted', binary() | [1..255]} | {'plaintext', _}) -> any().
decrypt(_Cipher, _Hash, _Iterations, _Secret, {plaintext, ClearText}) ->
    ClearText;
decrypt(Cipher, Hash, Iterations, Secret, {encrypted, Base64Binary}) ->
    IvLength = iv_length(Cipher),
    << Salt:16/binary, Ivec:IvLength/binary, Binary/bits >> = base64:decode(Base64Binary),
    Key = make_key(Cipher, Hash, Iterations, Secret, Salt),
    unpad(crypto:crypto_one_time(Cipher, Key, Ivec, Binary, false)).

%% Generate a key from a secret.

make_key(Cipher, Hash, Iterations, Secret, Salt) ->
    Key = pubkey_pbe:pbdkdf2(Secret, Salt, Iterations, key_length(Cipher),
        fun hmac/4, Hash, hash_length(Hash)),
    if
        Cipher =:= des3_cbc; Cipher =:= des3_cbf; Cipher =:= des3_cfb;
                Cipher =:= des_ede3; Cipher =:= des_ede3_cbc;
                Cipher =:= des_ede3_cbf; Cipher =:= des_ede3_cfb ->
            << A:8/binary, B:8/binary, C:8/binary >> = Key,
            [A, B, C];
        true ->
            Key
    end.

hmac(SubType, Key, Data, MacLength) ->
    crypto:macN(hmac, SubType, Key, Data, MacLength).

%% Functions to pad/unpad input to a multiplier of block size.

pad(Cipher, Data) ->
    BlockSize = block_size(Cipher),
    N = BlockSize - (byte_size(Data) rem BlockSize),
    Pad = list_to_binary(lists:duplicate(N, N)),
    <<Data/binary, Pad/binary>>.

unpad(Data) ->
    N = binary:last(Data),
    binary:part(Data, 0, byte_size(Data) - N).

hash_length(Type) ->
    maps:get(size, crypto:hash_info(Type)).

iv_length(Type) ->
    maps:get(iv_length, crypto:cipher_info(Type)).

key_length(Type) ->
    maps:get(key_length, crypto:cipher_info(Type)).

block_size(Type) ->
    maps:get(block_size, crypto:cipher_info(Type)).
