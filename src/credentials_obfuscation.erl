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

-export([encrypt/1,decrypt/1]).

encrypt(none) ->
    none;
encrypt(Term) ->
    credentials_obfuscation_pbe:encrypt(
        credentials_obfuscation_pbe:default_cipher(), credentials_obfuscation_pbe:default_hash(), credentials_obfuscation_pbe:default_iterations(), 
        credentials_obfuscation_app:passphrase(), Term).

decrypt(none) ->
    none;
decrypt(Base64EncryptedBinary) ->
    credentials_obfuscation_pbe:decrypt(
        credentials_obfuscation_pbe:default_cipher(), credentials_obfuscation_pbe:default_hash(), credentials_obfuscation_pbe:default_iterations(), 
        credentials_obfuscation_app:passphrase(), Base64EncryptedBinary).