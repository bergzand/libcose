/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose/crypto.h"

bool cose_crypto_is_hkdf(cose_algo_t alg)
{
    /* NOLINTNEXTLINE(hicpp-multiway-paths-covered) */
    switch(alg) {
#ifdef HAVE_ALGO_HMAC256
        case COSE_ALGO_HMAC256:
            return true;
#endif
        default:
            return false;
    }
}

int cose_crypto_hkdf_derive(const uint8_t *salt,
                                   size_t salt_len,
                                   const uint8_t *ikm,
                                   size_t ikm_length,
                                   const uint8_t *info,
                                   size_t info_length,
                                   uint8_t *out,
                                   size_t out_length, cose_algo_t alg) {
    /* NOLINTNEXTLINE(hicpp-multiway-paths-covered) */
    switch(alg) {
#ifdef HAVE_ALGO_HMAC256
        case COSE_ALGO_HMAC256:
            return cose_crypto_hkdf_derive_sha256(salt, salt_len, ikm,
                    ikm_length, info, info_length, out, out_length);
#endif
        default:
            return COSE_ERR_NOTIMPLEMENTED;
    }
}
