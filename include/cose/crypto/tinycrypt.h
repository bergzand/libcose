/*
 * Copyright (C) 2021 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cryto_tinycrypt Crypto glue layer, tinycrypt definitions
 * @ingroup     cose_crypto
 *
 * Crypto function api for glueing tinycrypt
 * @{
 *
 * @file
 * @brief       Crypto function api for glueing tinycrypt.
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_CRYPTO_TINYCRYPT_H
#define COSE_CRYPTO_TINYCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name list of provided algorithms
 *
 * @{
 */
#define HAVE_ALGO_ES256     /**< Sha256 support and some EC support */
#define HAVE_ALGO_ECDSA

#define HAVE_CURVE_P256     /**< EC NIST p256 curve support */

#define HAVE_ALGO_AESCCM
#if __has_include (<tinycrypt/hkdf.h>)
#define HAVE_ALGO_HMAC256
#endif

#define HAVE_ALGO_AESCCM_16_64_128 /**< AES CCM mode support with 16 bit length, 64 bit tag 128 bit key */
#define HAVE_ALGO_AESCCM_16_128_128 /**< AES CCM mode support with 16 bit length, 128 bit tag 128 bit key */
/** @} */

#ifdef __cplusplus
}
#endif

#endif

/** @} */

