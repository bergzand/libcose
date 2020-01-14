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

#include <crypto.h> /* tinydtls', that is */

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
    // Casts: discarding const -- see https://github.com/eclipse/tinydtls/issues/25
    int ret = dtls_encrypt(msg, msglen, c, (uint8_t*)npub, (uint8_t*)k, keysize, aad, aadlen);
    if (ret == msglen + COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES) {
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
    // Casts: discarding const -- see https://github.com/eclipse/tinydtls/issues/25
    int ret = dtls_decrypt(c, clen, msg, (uint8_t*)npub, (uint8_t*)k, keysize, aad, aadlen);
    if (ret == clen - COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES) {
        *msglen = ret;
        return COSE_OK;
    } else {
        return COSE_ERR_CRYPTO;
    }
}
