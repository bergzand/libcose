# libcose

Libcose is a C library aiming to implement the full COSE[1] standard.
Libcose is aimed at constrained devices without dynamic memory allocation,
libcose will never call malloc related calls by itself. However it does
require a simple block array allocator for cbor management.

Libcose implements modern ed25519 based signatures for signing. ECDSA based
signing and verification might be implemented at some point. RSA will probably
be skipped.

### Dependencies:

- cn-cbor[2]
- Either tweetNaCl[3] or Libsodium[4] as crypto library
- A memory block allocator (can be malloc/calloc based)

### building

To build a shared library from libcose:
```
make lib
```

Default libcose will try to link against libsodium.


[1]: https://tools.ietf.org/html/rfc8152
[2]: https://github.com/cabo/cn-cbor
[3]: https://tweetnacl.cr.yp.to/
[4]: https://github.com/jedisct1/libsodium
