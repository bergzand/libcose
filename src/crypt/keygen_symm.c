/*
 * Copyright (C) 2021 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Key material generators for symmetric key algorithms
 */

#include "cose/crypto.h"

extern cose_crypt_rng cose_crypt_get_random;
extern void *cose_crypt_rng_arg;

COSE_ssize_t cose_crypto_keygen_chachapoly(uint8_t *sk, size_t len)
{
    if (len < COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
        return COSE_ERR_NOMEM;
    }
    cose_crypt_get_random(cose_crypt_rng_arg, sk, COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
    return COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES;
}

/* random nonce generator, not collision safe */
size_t cose_crypto_aead_nonce_chachapoly(uint8_t *nonce, size_t len)
{
    if (len < COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES) {
        return 0;
    }
    cose_crypt_get_random(cose_crypt_rng_arg, nonce, COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES);
    return COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES;
}

COSE_ssize_t cose_crypto_keygen_aesgcm(uint8_t *buf, size_t len, cose_algo_t algo)
{
    (void)len;
    size_t keybytes = 0;
    switch(algo) {
        case COSE_ALGO_A128GCM:
            keybytes = COSE_CRYPTO_AEAD_AES128GCM_KEYBYTES;
            break;
        case COSE_ALGO_A192GCM:
            keybytes = COSE_CRYPTO_AEAD_AES192GCM_KEYBYTES;
            break;
        case COSE_ALGO_A256GCM:
            keybytes = COSE_CRYPTO_AEAD_AES256GCM_KEYBYTES;
            break;
        default:
            return COSE_ERR_NOTIMPLEMENTED;
    }
    if (len < keybytes) {
        return COSE_ERR_NOMEM;
    }
    if (!cose_crypt_get_random(cose_crypt_rng_arg, buf, keybytes)) {
        return keybytes;
    }
    return COSE_ERR_CRYPTO;
}
