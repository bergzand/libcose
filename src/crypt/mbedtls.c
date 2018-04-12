/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and mbedtls
 */

#include "cose.h"
#include "cose/intern.h"
#include "cose/crypto.h"
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern cose_crypt_rng cose_crypt_get_random;
extern void *cose_crypt_rng_arg;

static mbedtls_md_type_t _translate_md(cose_algo_t algo)
{
    switch(algo) {
        case COSE_ALGO_ES256:
            return MBEDTLS_MD_SHA256;
        case COSE_ALGO_ES384:
            return MBEDTLS_MD_SHA384;
        case COSE_ALGO_ES512:
            return MBEDTLS_MD_SHA512;
        default:
            return MBEDTLS_MD_NONE;
    }
}

static mbedtls_ecp_group_id _translate_curve(cose_curve_t algo)
{
    switch(algo) {
        case COSE_EC_CURVE_P256:
            return MBEDTLS_ECP_DP_SECP256R1;
        case COSE_EC_CURVE_P384:
            return MBEDTLS_ECP_DP_SECP384R1;
        case COSE_EC_CURVE_P521:
            return MBEDTLS_ECP_DP_SECP521R1;
        default:
            return MBEDTLS_ECP_DP_NONE;
    }
}

static int _get_key_params(mbedtls_ecdsa_context *ctx, const cose_key_t *key)
{
    size_t len = 0;
    switch(key->crv) {
        case COSE_EC_CURVE_P256:
            len = 32;
            mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1);
            break;
        case COSE_EC_CURVE_P384:
            len = 48;
            mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP384R1);
            break;
        case COSE_EC_CURVE_P521:
            len = 66;
            mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP521R1);
            break;
        default:
            return COSE_ERR_NOTIMPLEMENTED;
    }

    (void)len;
    mbedtls_ecp_point *pt = &ctx->Q;
    /* Construct key from cose_key_t */
    mbedtls_mpi_read_binary( &pt->X, key->x, MBEDTLS_ECP_MAX_BYTES);
    mbedtls_mpi_read_binary( &pt->Y, key->y, MBEDTLS_ECP_MAX_BYTES);
    mbedtls_mpi_lset( &pt->Z, 1 );
    mbedtls_mpi_read_binary( &ctx->d, key->d, MBEDTLS_ECP_MAX_BYTES);

    if (mbedtls_ecp_check_privkey( &ctx->grp, &ctx->d ) != 0 ) {
        return COSE_ERR_INVALID_PARAM;
    }

    if (mbedtls_ecp_check_pub_priv(ctx, ctx) != 0 ) {
        return COSE_ERR_INVALID_PARAM;
    }
    return COSE_OK;
}

size_t _hash(cose_algo_t algo, const uint8_t *msg, size_t msglen, uint8_t *hash)
{
    /* Algo determines hash function, curve determines ECDSA curve */
    switch(algo) {
        case COSE_ALGO_ES256:
            {
                mbedtls_sha256_context ctx;
                mbedtls_sha256_init(&ctx);
                mbedtls_sha256_starts(&ctx, 0);
                mbedtls_sha256_update(&ctx, msg, msglen);
                mbedtls_sha256_finish(&ctx, hash);
                return 32;
                break;
            }
        case COSE_ALGO_ES384:
            {
                mbedtls_sha512_context ctx;
                mbedtls_sha512_init(&ctx);
                mbedtls_sha512_starts(&ctx, 1);
                mbedtls_sha512_update(&ctx, msg, msglen);
                mbedtls_sha512_finish(&ctx, hash);
                return 48;
                break;
            }
        case COSE_ALGO_ES512:
            {
                mbedtls_sha512_context ctx;
                mbedtls_sha512_init(&ctx);
                mbedtls_sha512_starts(&ctx, 0);
                mbedtls_sha512_update(&ctx, msg, msglen);
                mbedtls_sha512_finish(&ctx, hash);
                return 64;
                break;
            }
        default:
            return 0;
    }
}

size_t cose_crypto_sig_size_ecdsa(cose_curve_t curve)
{
    (void)curve;
    return MBEDTLS_ECDSA_MAX_LEN;
}

void cose_crypto_keypair_ecdsa(cose_key_t *key, cose_curve_t curve)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    if (mbedtls_ecp_gen_key(_translate_curve(curve), &ctx, cose_crypt_get_random, cose_crypt_rng_arg) != 0) {
        printf("Key generation failed\n");
    }

    mbedtls_mpi_write_binary(&ctx.Q.X, key->x, MBEDTLS_ECP_MAX_BYTES);
    mbedtls_mpi_write_binary(&ctx.Q.Y, key->y, MBEDTLS_ECP_MAX_BYTES);
    mbedtls_mpi_write_binary( &ctx.d, key->d, MBEDTLS_ECP_MAX_BYTES);
    key->crv = curve;
}

int cose_crypto_sign_ecdsa(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg,  size_t msglen)
{
    unsigned char hash[64];
    memset(hash, 0, sizeof(hash));
    size_t hashlen = 0;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    if (_get_key_params(&ctx, key) != 0) {
        return COSE_ERR_INVALID_PARAM;
    }
    hashlen = _hash(key->algo, msg, msglen, hash);
    if (hashlen == 0) {
        return COSE_ERR_INVALID_PARAM;
    }

    if ( mbedtls_ecdsa_write_signature(&ctx, _translate_md(key->algo), hash, hashlen, (unsigned char *)sign, signlen, NULL, NULL) != 0) {
        return COSE_ERR_CRYPTO;
    }
    return COSE_OK;
}

int cose_crypto_verify_ecdsa(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, size_t msglen)
{
    unsigned char hash[64];
    memset(hash, 0, sizeof(hash));
    size_t hashlen = 0;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    if (_get_key_params(&ctx, key) != 0) {
        return COSE_ERR_INVALID_PARAM;
    }
    hashlen = _hash(key->algo, msg, msglen, hash);
    if (hashlen == 0) {
        return COSE_ERR_INVALID_PARAM;
    }

    if (mbedtls_ecdsa_read_signature(&ctx, hash, hashlen, (unsigned char *)sign, signlen) != 0) {
        return COSE_ERR_CRYPTO;
    }
    return COSE_OK;
}
