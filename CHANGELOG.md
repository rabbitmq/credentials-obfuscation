# Changelog

## [v3.5.0](https://github.com/rabbitmq/credentials-obfuscation/tree/v3.5.0) (2025-03-24)

[Full Changelog](https://github.com/rabbitmq/credentials-obfuscation/compare/v3.4.0...v3.5.0)

**Implemented enhancements:**

- Add cuttlefish schema [\#28](https://github.com/rabbitmq/credentials-obfuscation/issues/28)

**Merged pull requests:**

- Prepare for v3.5.0 [\#34](https://github.com/rabbitmq/credentials-obfuscation/pull/34) ([lukebakken](https://github.com/lukebakken))
- Remove defaults and unset if undefined [\#30](https://github.com/rabbitmq/credentials-obfuscation/pull/30) ([SimonUnge](https://github.com/SimonUnge))
- Add schema file [\#29](https://github.com/rabbitmq/credentials-obfuscation/pull/29) ([SimonUnge](https://github.com/SimonUnge))

## [v3.4.0](https://github.com/rabbitmq/credentials-obfuscation/tree/v3.4.0) (2023-05-04)

[Full Changelog](https://github.com/rabbitmq/credentials-obfuscation/compare/v3.3.0...v3.4.0)

- Copy paste some crypto type definitions from OTP to make dialyzer happy
- Exclude `shake128` and `shake256` (new hashing algorithms introduced in OTP26) from the tests as they don't support what we do
- Add OTP26 to CI
- Remove OTP23 from CI

## [v3.3.0](https://github.com/rabbitmq/credentials-obfuscation/tree/v3.3.0) (2023-03-04)

[Full Changelog](https://github.com/rabbitmq/credentials-obfuscation/compare/v3.2.0...v3.3.0)

**Closed issues:**

- Remove rebar3\_hex plugin from rebar.config [\#22](https://github.com/rabbitmq/credentials-obfuscation/issues/22)

**Merged pull requests:**

- Update README.md [\#24](https://github.com/rabbitmq/credentials-obfuscation/pull/24) ([L1nY4n](https://github.com/L1nY4n))
- Include rebar3\_hex in project\_plugins, not plugins [\#23](https://github.com/rabbitmq/credentials-obfuscation/pull/23) ([newmanjeff](https://github.com/newmanjeff))

## Changes between 3.1.0 and 3.2.0 (Nov 7, 2022)

GitHub milestone: [link](https://github.com/rabbitmq/credentials-obfuscation/milestone/8closed=1)

## Changes Between 2.4.0 and 3.0.0 (May 2, 2022)

### Fallback Secret Support

An alternative secret now can be provided to be used as fallback.
This is useful for key migrations (rotations, upgrades, and so on)
when some stored pieces of state can still use the old key.

Contributed by @luos.

GitHub issue: [rabbitmq/credentials-obfuscation#15](https://github.com/rabbitmq/credentials-obfuscation/pull/15)

### Support for Erlang/OTP 25

The library supports Erlang 25 and drops support for Erlang versions < 22.3.

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


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
