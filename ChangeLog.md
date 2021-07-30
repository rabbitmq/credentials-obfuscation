# Change Log

## Changes Between 2.4.0 and 2.5.0 (unreleased)

No changes yet.

## Changes Between 2.3.0 and 2.4.0 (February 18, 2021)

### Support for Erlang/OTP 24 and the new Crypto API

The library now supports Erlang 24 and drops support for Erlang versions < 22.1.

Contributed by Dominic @dmorneau Morneau.

GitHub issue: [#10](https://github.com/rabbitmq/credentials-obfuscation/pull/10).


## Changes Between 2.2.0 and 2.3.0 (December 18, 2020)

### Defaults for Better Efficiency

The library now uses a weaker cipher suite by default for a significant
gain in efficiency:

 * AES CBC with a 128-bit key
 * SHA-256 instead of SHA-512 for hashing
 * A single iteration instead of 1000

AES CBC with a 128-bit key is a reasonable default
for this library's use case, in-memory obfuscation of transient process state.

Users who need to use a suite with stronger security
guarantees, such as AES CBC with a 256-bit key,
can override the default:

``` erl
ok = application:set_env(credentials_obfuscation, cipher, aes_cbc256),
ok = application:set_env(credentials_obfuscation, hash, sha512),
ok = application:set_env(credentials_obfuscation, iterations, 300).
```

Contributed by CloudAMQP.

GitHub issue: [#9](https://github.com/rabbitmq/credentials-obfuscation/pull/9)

## Changes Between 2.1.0 and 2.2.0 (August 18, 2020)

### List Values are Coerced to Binaries

This library works with binary inputs and outputs. Input list values will now be
converted to binaries automatically for convenience. Decrypted values will always
be returned as binaries.

For the purpose of credentials, the two types are usually semantically equivalent.
When that's not the case, we highly recommend using binaries exclusively instead
of a mix of binaries and lists (Erlang strings).


## Changes Between 2.1.0 and 2.1.1 (July 29h, 2020)

### More Graceful Handling of Encryption Timeouts

Should an encryption operation time out (can happen on nodes nearly maxing out their scheduler/CPU resources),
a plain text value is returned to the caller. This is similar to how other
"encrypting was not possible" scenarios are handled. The caller must
decide whether using unencrypted values can be appropriate in such low probability scenarios
or must be treated as an error.

GitHub issue: [#7](https://github.com/rabbitmq/credentials-obfuscation/pull/7)


## Changes Between 2.0.0 and 2.1.0 (July 20th, 2020)

### License Change

The library is now double-licensed under the Apache Software License 2.0
and Mozilla Public License 2.0 (previously: under the ASL2 and Mozilla Public License 1.1).

### Minimum Supported Erlang Version Bump

The library now requires OTP 21.3 or a later version.


## Changes Between 1.x and 2.0.0

### Secret Seeding

The application now requires an explicitly provided secret for seeding
of private key generation. This is done using the `credentials_obfuscation:set_secret/1` function
after the application was started and before it is used.
