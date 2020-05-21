# Credential Obfuscator

This is a small library OTP application that acts as a help. It encrypts and decrypts sensitive data
typically stored in processes state with a one-off key (key material is generated on node start).
One example of such sensitive data is credentials used to access remote services.

This is necessary to avoid the sensitive values logged when process state is dumped by
the Erlang runtime (`error_logger`).

Note that this application **cannot protect against heap dumping attacks** and only helps
avoid sensitive data appearing in log files.

# Usage

First, make the `credentials_obfuscation` application a dependency of your project.

Then, during the start-up of your application, and after the `credentials_obfuscation` application starts, provide the secret value:


```
CookieBin = atom_to_binary(erlang:get_cookie(), latin1)),
credentials_obfuscation:set_secret(CookieBin)
```

To use a random value, do the following:

```
Bytes = crypto:strong_rand_bytes(128),
credentials_obfuscation:set_secret(Bytes)
```

## License and Copyright

See [LICENSE](./LICENSE).

(c) 2019-2020 Vmware, Inc or its affiliates.
