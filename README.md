# libcose

[![Build Status](https://api.cirrus-ci.com/github/bergzand/libcose.svg)](https://cirrus-ci.com/github/bergzand/libcose)

Libcose is a C library aiming to implement the full [COSE] standard.
Libcose is aimed at constrained devices without dynamic memory allocation,
libcose will never call malloc related calls by itself. However it does
require a simple block array allocator for cbor management.

Libcose implements modern ed25519 based signatures for signing. ECDSA based
signing and verification is implemented using Mbed TLS. RSA will probably
be skipped.

### Dependencies:

- [NanoCBOR]
- Either [HACL-C], [libsodium] or [mbed TLS] as crypto library

### Building

To build a shared library from libcose:

```
make lib
```

Default libcose will try to link against libsodium for the crypto. Since
versions after v0.3.x libcose depends on tinycbor instead of cn-cbor.

### Testing

libcose is supplied with a test suite covering most cases. Testing requires
CUnit as test framework and [tinycbor] as additional CBOR library.
Running al tests is done with:

```
make test
```

### Contributing

Open an issue, PR, the usual. Builds must pass before merging. Currently
Travis tests the full test suite. In addition Travis also runs clang-tidy
to check for simple style and code mistakes.

### Limitations

Due to time constraints, for now only signing is implemented. Contributions
for encryption and authentication is of course welcome.

As libcose is aimed at constrained devices a number of configurables are
compile time defined. This includes the number of headers and the number
signatures that are allowed in a single signature structure.

[COSE]: https://tools.ietf.org/html/rfc8152
[NanoCBOR]: https://github.com/bergzand/NanoCBOR
[tinycbor]: https://github.com/intel/tinycbor
[libsodium]: https://github.com/jedisct1/libsodium
[HACL-C]: https://github.com/mitls/hacl-c
[mbed TLS]: https://tls.mbed.org/
