# libcose

[![Build Status](https://travis-ci.org/bergzand/libcose.svg?branch=master)](https://travis-ci.org/bergzand/libcose)

Libcose is a C library aiming to implement the full [COSE] standard.
Libcose is aimed at constrained devices without dynamic memory allocation,
libcose will never call malloc related calls by itself. However it does
require a simple block array allocator for cbor management.

Libcose implements modern ed25519 based signatures for signing. ECDSA based
signing and verification might be implemented at some point. RSA will probably
be skipped.

### Dependencies:

- [cn-cbor]
- Either [TweetNaCl] or [libsodium] as crypto library
- A memory block allocator (can be malloc/calloc based)

### Building

To build a shared library from libcose:

```
make lib
```

Default libcose will try to link against libsodium for the crypto. Note that
libcose also requires cn-cbor compiled with context pointer support. When
building cn-cbor, please use `cmake -Duse_context=ON` to enable the context
pointer.

### Testing

libcose is supplied with a test suite covering most cases. Testing requires
CUnit as test framework. Running al tests is done with

```
make test
```

### Limitations

Due to time constraints, for now only signing is implemented. Contributions
for encryption and authentication is of course welcome.

As libcose is aimed at constrained devices a number of configurables are
compile time defined. This includes the number of headers and the number
signatures that are allowed in a single signature structure.

[COSE]: https://tools.ietf.org/html/rfc8152
[cn-cbor]: https://github.com/cabo/cn-cbor
[TweetNaCl]: https://tweetnacl.cr.yp.to/
[libsodium]: https://github.com/jedisct1/libsodium
