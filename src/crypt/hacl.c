/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and HaCl*
 */

#include "cose.h"
#include "cose/crypto.h"
#include "cose/crypto/hacl.h"
#include "cose/crypto/selectors.h"
#include <haclnacl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void Hacl_Ed25519_sign(uint8_t *signature, uint8_t *secret, uint8_t *msg, uint32_t len1);
extern bool Hacl_Ed25519_verify(uint8_t *public, uint8_t *msg, uint32_t len1, uint8_t *signature);
extern cose_crypt_rng cose_crypt_get_random;
extern void *cose_crypt_rng_arg;

#ifdef CRYPTO_HACL_INCLUDE_CHACHAPOLY
int cose_crypto_aead_encrypt_chachapoly(uint8_t *c,
                                        size_t *clen,
                                        const uint8_t *msg,
                                        size_t msglen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k)
{
    uint8_t *mac = c + msglen;
    *clen = msglen + COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;
    int res = aead_chacha20_poly1305_encrypt(c, mac, (uint8_t*)msg, msglen, (uint8_t*)aad, aadlen, (uint8_t*)k, (uint8_t*)npub);
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
    const uint8_t *mac = c + clen - COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;
    int res = aead_chacha20_poly1305_decrypt((uint8_t *)msg,
            (uint8_t*)c,
            clen - COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES,
            (uint8_t *)mac,
            (uint8_t*)aad,
            aadlen,
            (uint8_t*)k,
            (uint8_t*)npub);
    *msglen = clen - COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;
    return res;
}
#endif /* CRYPTO_HACL_INCLUDE_CHACHAPOLY */

#ifdef CRYPTO_HACL_INCLUDE_ED25519
int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen)
{
    uint8_t skey[COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES +
        COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
    memcpy(skey, key->d, COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES);
    memcpy(skey + COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES, key->x,
            COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES);
    Hacl_Ed25519_sign(sign, skey, msg, msglen);
    *signlen = (size_t)COSE_CRYPTO_SIGN_ED25519_SIGNBYTES;
    return COSE_OK;
}

int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen)
{
    if (signlen != COSE_CRYPTO_SIGN_ED25519_SIGNBYTES) {
        return COSE_ERR_CRYPTO;
    }
    if (Hacl_Ed25519_verify(key->x, msg, msglen, (uint8_t*)sign))
    {
        return COSE_OK;
    }
    return COSE_ERR_CRYPTO;
}

void cose_crypto_keypair_ed25519(cose_key_t *key)
{
    uint8_t skey[COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES +
        COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
    crypto_sign_keypair(key->x, skey);
    memcpy(key->d, skey, COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES);
}
#endif /* CRYPTO_HACL_INCLUDE_ED25519 */
