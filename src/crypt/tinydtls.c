/*
 * Copyright (C) 2020 Christian Amsüss <christian@amsuess.com> and Ericsson AB
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and tinydtls
 */

#include "cose.h"
#include "cose/crypto.h"

#include "cose/crypto/selectors.h"

#include <crypto.h> /* tinydtls', that is */
#include <hmac.h> /* tinydtls', that is */

int cose_crypto_aead_encrypt_aesccm(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize)
{
    const dtls_ccm_params_t params = { npub, 8, 2 };
    int ret = dtls_encrypt_params(&params, msg, msglen, c, (uint8_t*)k, keysize, aad, aadlen);
    if (ret >= 0 && (size_t)ret == msglen + COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES) {
        *clen = ret;
        return COSE_OK;
    } else {
        return COSE_ERR_CRYPTO;
    }
}

int cose_crypto_aead_decrypt_aesccm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize)
{
    const dtls_ccm_params_t params = { npub, 8, 2 };
    int ret = dtls_decrypt_params(&params, c, clen, msg, (uint8_t*)k, keysize, aad, aadlen);
    if (ret >= 0 && (size_t)ret == clen - COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES) {
        *msglen = ret;
        return COSE_OK;
    } else {
        return COSE_ERR_CRYPTO;
    }
}

#ifdef CRYPTO_TINYDTLS_INCLUDE_HKDFSHA256
int cose_crypto_hkdf_derive_sha256(const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_length,
        const uint8_t *info,
        size_t info_length,
        uint8_t *out,
        size_t out_length)
{
#define SHA256_OUTPUT_BYTES 32
    uint8_t prk[SHA256_OUTPUT_BYTES];

    /* Extract step*/
    {
        dtls_hmac_context_t hmac_ctx;

        dtls_hmac_init(&hmac_ctx, salt, salt_len);
        dtls_hmac_update(&hmac_ctx, ikm, ikm_length);
        dtls_hmac_finalize(&hmac_ctx, prk);
    }

    /* Expand step */

    uint8_t slice[SHA256_OUTPUT_BYTES];
    size_t slice_len = SHA256_OUTPUT_BYTES;
    uint8_t counter[1] = {0x01};
    dtls_hmac_context_t state;
    size_t rounds = (out_length + SHA256_OUTPUT_BYTES - 1) / SHA256_OUTPUT_BYTES;
    for (size_t i = 0; i < rounds; ++i) {
        size_t offset = i * SHA256_OUTPUT_BYTES;
        *counter = i + 1;
        dtls_hmac_init(&state, prk, SHA256_OUTPUT_BYTES);
        if (i > 0) {
            dtls_hmac_update(&state, slice, slice_len);
        }
        dtls_hmac_update(&state, info, info_length);
        dtls_hmac_update(&state, counter, 1);
        dtls_hmac_finalize(&state, slice);
        if (i + 1 == rounds) {
            slice_len = out_length - offset;
        }
        memcpy(out + offset, slice, slice_len);
    }

    return COSE_OK;
}
#endif /* CRYPTO_TINYDTLS_INCLUDE_HKDFSHA256 */
