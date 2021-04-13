/*
 * Copyright (C) 2019 Koen Zandberg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_crypto_selectors Crypto logic to select implementations
 * @ingroup     cose
 *
 * @{
 *
 * @file
 * @brief       Logic to select different crypto implementations
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_CRYPTO_SELECTORS_H
#define COSE_CRYPTO_SELECTORS_H

/**
 * @name Ed25519 selector
 */
#ifdef CRYPTO_SODIUM
#define CRYPTO_SODIUM_INCLUDE_ED25519
#elif defined(CRYPTO_MONOCYPHER)
#define CRYPTO_MONOCYPHER_INCLUDE_ED25519
#elif defined(CRYPTO_C25519)
#define CRYPTO_C25519_INCLUDE_ED25519
#elif defined(CRYPTO_HACL)
#define CRYPTO_HACL_INCLUDE_ED25519
#endif
/** @} */

/**
 * @name ChaCha20Poly1305 selector
 */
#ifdef CRYPTO_SODIUM
#define CRYPTO_SODIUM_INCLUDE_CHACHAPOLY
#elif defined(CRYPTO_MONOCYPHER)
#define CRYPTO_MONOCYPHER_INCLUDE_CHACHAPOLY
#elif defined(CRYPTO_MBEDTLS)
#define CRYPTO_MBEDTLS_INCLUDE_CHACHAPOLY
#elif defined(CRYPTO_HACL)
#define CRYPTO_HACL_INCLUDE_CHACHAPOLY
#endif
/** @} */
#endif /* COSE_CRYPTO_SELECTORS_H */

#if defined(HAVE_ALGO_AES128GCM) || \
    defined(HAVE_ALGO_AES192GCM) || \
    defined(HAVE_ALGO_AES256GCM)
#define HAVE_ALGO_AESGCM    /**< AES GCM mode support */
#endif

#if defined(HAVE_ALGO_AES128CCM_16_64_128) || \
    defined(HAVE_ALGO_AES128CCM_64_64_128) || \
    defined(HAVE_ALGO_AES128CCM_16_128_128) || \
    defined(HAVE_ALGO_AES128CCM_64_128_128) || \
    defined(HAVE_ALGO_AES128CCM_16_64_256) || \
    defined(HAVE_ALGO_AES128CCM_64_64_256) || \
    defined(HAVE_ALGO_AES128CCM_16_128_256) || \
    defined(HAVE_ALGO_AES128CCM_64_128_256)
#define HAVE_ALGO_AESCCM
#endif

/** @} */
