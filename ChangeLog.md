# Change Log

## Changes Between 2.0.0 and 2.1.0

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