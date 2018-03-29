# Feature list

As libcose does not yet support the full COSE rfc, this document presents a
list of features that are supported at the moment by this library

## Generic

### Header operations
- [x] Setting headers with integer based keys
- [x] Getting headers with integer based keys
- [ ] Setting headers with string based keys
- [ ] Getting headers with string based keys
 
## Signing
 
- [x] Signing
- [x] Verification
- [x] Signing with multiple keys
- [x] Verification of signing structs with multiple keys
- [x] Sign1 support for signing
- [x] Sign1 support for verification
- [ ] Countersignature support
- [ ] External Payload support
- [x] Additional authenticated data support
- [x] Untagged support
- [x] Tagged support
- [x] Signature body headers
- [ ] Signature per signer headers

- [x] EdDSA based signing and verification
- [ ] ECDSA basedi signing and verification
