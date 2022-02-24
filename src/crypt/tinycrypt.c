/*
 * Copyright (C) 2021 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and tinycrypt
 */

#include "cose.h"
#include "cose/intern.h"
#include "cose/crypto.h"
#include "cose/crypto/selectors.h"
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/sha256.h>
#if __has_include (<tinycrypt/hkdf.h>)
#include <tinycrypt/hkdf.h>
#endif

extern cose_crypt_rng cose_crypt_get_random;
extern void *cose_crypt_rng_arg;

/* tinycrypt random function */
int default_CSPRNG(uint8_t *dest, unsigned size)
{
    cose_crypt_get_random(cose_crypt_rng_arg, dest, size);
    return 1;
}

static int _mac_len(cose_algo_t algo) {
    switch(algo) {
        case COSE_ALGO_AESCCM_16_64_128:
        case COSE_ALGO_AESCCM_16_64_256:
        case COSE_ALGO_AESCCM_64_64_128:
        case COSE_ALGO_AESCCM_64_64_256:
            return COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES;
        case COSE_ALGO_AESCCM_16_128_128:
        case COSE_ALGO_AESCCM_16_128_256:
        case COSE_ALGO_AESCCM_64_128_128:
        case COSE_ALGO_AESCCM_64_128_256:
            return COSE_CRYPTO_AEAD_AESCCM_16_128_128_ABYTES;
        default:
            return 0;
    }
}

static int _set_config(struct tc_ccm_mode_struct *ctx,
                       struct tc_aes_key_sched_struct *key,
                       cose_algo_t algo,
                       const uint8_t *npub,
                       const uint8_t *k)
{
    int res = 0;
    tc_aes128_set_encrypt_key(key, k); /* Set the key */

    switch(algo) {
        case COSE_ALGO_AESCCM_16_64_256:
        case COSE_ALGO_AESCCM_64_64_256:
        case COSE_ALGO_AESCCM_16_128_256:
        case COSE_ALGO_AESCCM_64_128_256:
        case COSE_ALGO_AESCCM_64_64_128:
        case COSE_ALGO_AESCCM_64_128_128:
            return COSE_ERR_NOTIMPLEMENTED;
        case COSE_ALGO_AESCCM_16_64_128:
            res = tc_ccm_config(ctx, key, (uint8_t*)npub, 13, 8);
            break;
        case COSE_ALGO_AESCCM_16_128_128:
            res = tc_ccm_config(ctx, key, (uint8_t*)npub, 13, 16);
            break;
        default:
            return COSE_ERR_CRYPTO;
    }
    return res == TC_CRYPTO_FAIL ? COSE_ERR_CRYPTO : COSE_OK;
}


int cose_crypto_aead_encrypt_aesccm(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo)
    /* Algo determines the key, tag and nonce size */
{
    struct tc_ccm_mode_struct ctx;
    struct tc_aes_key_sched_struct key;

    int res = _set_config(&ctx, &key, algo, npub, k);
    if (res != COSE_OK) {
        return res;
    }

    *clen = msglen + _mac_len(algo);

    res = tc_ccm_generation_encryption(c, *clen, aad, aadlen, msg, msglen, &ctx);

    return res ? COSE_OK : COSE_ERR_CRYPTO;
}

int cose_crypto_aead_decrypt_aesccm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo)
{
    struct tc_ccm_mode_struct ctx;
    struct tc_aes_key_sched_struct key;

    int res = _set_config(&ctx, &key, algo, npub, k);
    if (res != COSE_OK) {
        return res;
    }
    *msglen = clen - _mac_len(algo);

    res = tc_ccm_decryption_verification(msg, *msglen,
                                         aad, aadlen, c, clen, &ctx);

    return res ? COSE_OK : COSE_ERR_CRYPTO;
}

size_t cose_crypto_sig_size_ecdsa(cose_curve_t curve)
{
    (void)curve;
    return COSE_CRYPTO_SIGN_P256_SIGNBYTES;
}

void cose_crypto_keypair_ecdsa(cose_key_t *key, cose_curve_t curve)
{
    (void)curve; /* Only COSE_EC_CURVE_P256 supported */
    uint8_t public[64];

    uECC_set_rng(default_CSPRNG);

    uECC_make_key(public, key->d, uECC_secp256r1());

    memcpy(key->x, public, 32);
    memcpy(key->y, public + 32, 32);

    key->crv = COSE_EC_CURVE_P256;
}

int cose_crypto_sign_ecdsa(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg,  size_t msglen)
{
    struct tc_sha256_state_struct ctx;
    uint8_t hash[32];

    uECC_set_rng(default_CSPRNG);

    tc_sha256_init(&ctx);
    tc_sha256_update(&ctx, msg, msglen);
    tc_sha256_final(hash, &ctx);

    int res = uECC_sign(key->d, hash, sizeof(hash), sign, uECC_secp256r1());
    *signlen = COSE_CRYPTO_SIGN_P256_SIGNBYTES;
    return res ? COSE_OK : COSE_ERR_CRYPTO;
}

int cose_crypto_verify_ecdsa(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, size_t msglen)
{
    (void)signlen;
    struct tc_sha256_state_struct ctx;
    uint8_t hash[32];
    uint8_t pubkey[64];

    memcpy(pubkey, key->x, 32);
    memcpy(pubkey + 32, key->y, 32);

    if (uECC_valid_public_key(pubkey, uECC_secp256r1()) < 0) {
        return COSE_ERR_CRYPTO;
    }

    tc_sha256_init(&ctx);
    tc_sha256_update(&ctx, msg, msglen);
    tc_sha256_final(hash, &ctx);


    int res = uECC_verify(pubkey, hash, sizeof(hash), (uint8_t*)sign, uECC_secp256r1());
    return res ? COSE_OK : COSE_ERR_CRYPTO;
}

#ifdef CRYPTO_TINYCRYPT_INCLUDE_HKDFSHA256
int cose_crypto_hkdf_derive_sha256(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *ikm, size_t ikm_length,
                                   const uint8_t *info, size_t info_length,
                                   uint8_t *out, size_t out_length)
{
    uint8_t prk[TC_SHA256_DIGEST_SIZE];

    int ret = tc_hkdf_extract(ikm, ikm_length, salt, salt_len, prk);

    if (ret != TC_CRYPTO_SUCCESS) {
        return COSE_ERR_CRYPTO;
    }

    ret = tc_hkdf_expand(prk, info, info_length, out_length, out);

    if (ret != TC_CRYPTO_SUCCESS) {
        return COSE_ERR_CRYPTO;
    }
    return COSE_OK;
}
#endif /* CRYPTO_TINYCRYPT_INCLUDE_HKDFSHA256 */
