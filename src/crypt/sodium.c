/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and libsodium
 */

#include "cose.h"
#include "cose/crypto.h"
#include "cose/crypto/selectors.h"
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef CRYPTO_SODIUM_INCLUDE_CHACHAPOLY
int cose_crypto_aead_encrypt_chachapoly(uint8_t *c,
                                        size_t *clen,
                                        const uint8_t *msg,
                                        size_t msglen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k)
{
    unsigned long long cipherlen = 0;
    int res = crypto_aead_chacha20poly1305_ietf_encrypt((unsigned char*)c, &cipherlen, (const unsigned char*)msg, msglen, (const unsigned char *)aad, aadlen, NULL, (const unsigned char*)npub, (const unsigned char*)k);
    *clen = cipherlen;
    return res;
}

int cose_crypto_aead_decrypt_chachapoly(uint8_t *msg,
                                        size_t *msglen,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k)
{
    unsigned long long messagelen = 0;
    int res = crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char *)msg,
            &messagelen,
            NULL,
            (const unsigned char*)c,
            clen,
            (const unsigned char *)aad,
            aadlen,
            (const unsigned char*)npub,
            (const unsigned char *)k);
    *msglen = messagelen;
    return res;
}

COSE_ssize_t cose_crypto_keygen_chachapoly(uint8_t *sk, size_t len)
{
    if (len < crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        return COSE_ERR_NOMEM;
    }
    randombytes_buf((unsigned char*)sk,
                    crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    return (COSE_ssize_t)crypto_aead_chacha20poly1305_ietf_KEYBYTES;
}

size_t cose_crypto_aead_nonce_chachapoly(uint8_t *nonce, size_t len)
{
    if (len < crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        return 0;
    }
    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    return crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
}
#endif /* CRYPTO_SODIUM_INCLUDE_CHACHAPOLY */

#ifdef CRYPTO_SODIUM_INCLUDE_ED25519
int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen)
{
    unsigned long long int signature_len = 0;
    uint8_t skey[crypto_sign_SECRETKEYBYTES];
    memcpy(skey, key->d, COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES);
    memcpy(skey + COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES, key->x,
            COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES);

    crypto_sign_detached(sign, &signature_len, msg, msglen, (unsigned char *)skey);
    *signlen = (size_t)signature_len;
    return COSE_OK;
}

int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen)
{
    (void)signlen;
    return crypto_sign_verify_detached(sign, msg, msglen, key->x);
}

void cose_crypto_keypair_ed25519(cose_key_t *key)
{
    uint8_t skey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(key->x, skey);
    memcpy(key->d, skey, COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES);
}

size_t cose_crypto_sig_size_ed25519(void)
{
    return crypto_sign_BYTES;
}

int cose_crypto_hkdf_derive_sha256(const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_length,
        const uint8_t *info,
        size_t info_length,
        uint8_t *out,
        size_t out_length)
{
    uint8_t prk[crypto_auth_hmacsha256_KEYBYTES];

    if (salt_len == crypto_auth_hmacsha256_KEYBYTES) {
        crypto_auth_hmacsha256(prk, ikm, ikm_length, salt);
    } else if (salt_len < crypto_auth_hmacsha256_KEYBYTES) {
        uint8_t padding[crypto_auth_hmacsha256_KEYBYTES];
        memset(padding, 0, crypto_auth_hmacsha256_KEYBYTES);
        memcpy(padding, salt, salt_len);
        crypto_auth_hmacsha256(prk, ikm, ikm_length, padding);
    } else {
        return COSE_ERR_INVALID_PARAM;
    }

    uint8_t slice[crypto_auth_hmacsha256_BYTES];
    size_t slice_len = crypto_auth_hmacsha256_BYTES;
    uint8_t counter[1] = {0x01};
    crypto_auth_hmacsha256_state state;
    size_t rounds = out_length / crypto_auth_hmacsha256_BYTES;
    if (out_length % crypto_auth_hmacsha256_BYTES > 0) {
        rounds++;
    }
    for (size_t i = 0; i < rounds; ++i) {
        size_t offset = i * crypto_auth_hmacsha256_BYTES;
        *counter = i + 1;
        crypto_auth_hmacsha256_init(&state, prk, crypto_auth_hmacsha256_KEYBYTES);
        if (i > 0) {
            crypto_auth_hmacsha256_update(&state, slice, slice_len);
        }
        crypto_auth_hmacsha256_update(&state, info, info_length);
        crypto_auth_hmacsha256_update(&state, counter, 1);
        crypto_auth_hmacsha256_final(&state, slice);
        if (i + 1 == rounds) {
            slice_len = out_length - offset;
        }
        memcpy(out + offset, slice, slice_len);
    }

    return COSE_OK;
}

#endif /* CRYPTO_SODIUM_INCLUDE_ED25519 */
