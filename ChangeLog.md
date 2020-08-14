# Change Log

## Changes Between 2.2.0 and 2.3.0 (in development)

## Changes Between 2.1.0 and 2.2.0 (in development)

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
