/*
 * Copyright (C) 2022 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_crypto_keyssizes key size defines
 * @ingroup     cose_crypto
 *
 * Global cose crypto-related defines
 * @{
 *
 * @file
 * @brief       API definitions for crypto operations
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_CRYPTO_KEYSIZES_H
#define COSE_CRYPTO_KEYSIZES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Common crypto size definitions
 * @{
 */

/**
 * @brief Ed25519 secret key size
 */
#define COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES         32U

/**
 * @brief Ed25519 public key size
 */
#define COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES         32U

/**
 * @brief Ed25519 signature size
 */
#define COSE_CRYPTO_SIGN_ED25519_SIGNBYTES              64U

/**
 * @brief Curve secp256r1 secret key size
 */
#define COSE_CRYPTO_SIGN_P256_SECRETKEYBYTES            32U

/**
 * @brief Curve secp256r1 public key size
 */
#define COSE_CRYPTO_SIGN_P256_PUBLICKEYBYTES            32U

/**
 * @brief Curve secp256r1 signature size
 */
#define COSE_CRYPTO_SIGN_P256_SIGNBYTES                 64U

/**
 * @brief Curve secp384r1 secret key size
 */
#define COSE_CRYPTO_SIGN_P384_SECRETKEYBYTES            48U

/**
 * @brief Curve secp384r1 public key size
 */
#define COSE_CRYPTO_SIGN_P384_PUBLICKEYBYTES            48U

/**
 * @brief Curve secp384r1 signature size
 */
#define COSE_CRYPTO_SIGN_P384_SIGNBYTES                 96U

/**
 * @brief Curve secp521r1 secret key size
 */
#define COSE_CRYPTO_SIGN_P521_SECRETKEYBYTES            66U

/**
 * @brief Curve secp521r1 public key size
 */
#define COSE_CRYPTO_SIGN_P521_PUBLICKEYBYTES            66U

/**
 * @brief Curve secp521r1 signature size
 */
#define COSE_CRYPTO_SIGN_P521_SIGNBYTES                 132U

/**
 * @brief ChaCha20Poly1305 key size
 */
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES      32U

/**
 * @brief ChaCha20Poly1305 key size
 */
#define COSE_CRYPTO_SECRET_CHACHA20POLY1305_KEYBYTES    32U

/**
 * @brief ChaCha20Poly1305 nonce size
 */
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES    12U

/**
 * @brief ChaCha20Poly1305 authentication tag size
 */
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES        16U


#define COSE_CRYPTO_AEAD_AESGCM_NONCEBYTES      12
#define COSE_CRYPTO_AEAD_AESGCM_ABYTES          16

#define COSE_CRYPTO_AEAD_AES128GCM_KEYBYTES     16
#define COSE_CRYPTO_AEAD_AES128GCM_NONCEBYTES   COSE_CRYPTO_AEAD_AESGCM_NONCEBYTES
#define COSE_CRYPTO_AEAD_AES128GCM_ABYTES       COSE_CRYPTO_AEAD_AESGCM_ABYTES

#define COSE_CRYPTO_AEAD_AES192GCM_KEYBYTES     24
#define COSE_CRYPTO_AEAD_AES192GCM_NONCEBYTES   COSE_CRYPTO_AEAD_AESGCM_NONCEBYTES
#define COSE_CRYPTO_AEAD_AES192GCM_ABYTES       COSE_CRYPTO_AEAD_AESGCM_ABYTES

#define COSE_CRYPTO_AEAD_AES256GCM_KEYBYTES     32
#define COSE_CRYPTO_AEAD_AES256GCM_NONCEBYTES   COSE_CRYPTO_AEAD_AESGCM_NONCEBYTES
#define COSE_CRYPTO_AEAD_AES256GCM_ABYTES       COSE_CRYPTO_AEAD_AESGCM_ABYTES

#define COSE_CRYPTO_AEAD_AESCCM_16_64_128_KEYBYTES      16
#define COSE_CRYPTO_AEAD_AESCCM_16_64_128_NONCEBYTES    13
#define COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES        8

#define COSE_CRYPTO_AEAD_AESCCM_64_64_128_KEYBYTES      16
#define COSE_CRYPTO_AEAD_AESCCM_64_64_128_NONCEBYTES    7
#define COSE_CRYPTO_AEAD_AESCCM_64_64_128_ABYTES        8

#define COSE_CRYPTO_AEAD_AESCCM_16_128_128_KEYBYTES      16
#define COSE_CRYPTO_AEAD_AESCCM_16_128_128_NONCEBYTES    13
#define COSE_CRYPTO_AEAD_AESCCM_16_128_128_ABYTES        16

#define COSE_CRYPTO_AEAD_AESCCM_64_128_128_KEYBYTES      16
#define COSE_CRYPTO_AEAD_AESCCM_64_128_128_NONCEBYTES    7
#define COSE_CRYPTO_AEAD_AESCCM_64_128_128_ABYTES        16

#define COSE_CRYPTO_AEAD_AESCCM_16_64_256_KEYBYTES      32
#define COSE_CRYPTO_AEAD_AESCCM_16_64_256_NONCEBYTES    13
#define COSE_CRYPTO_AEAD_AESCCM_16_64_256_ABYTES        8

#define COSE_CRYPTO_AEAD_AESCCM_64_64_256_KEYBYTES      32
#define COSE_CRYPTO_AEAD_AESCCM_64_64_256_NONCEBYTES    7
#define COSE_CRYPTO_AEAD_AESCCM_64_64_256_ABYTES        8

#define COSE_CRYPTO_AEAD_AESCCM_16_128_256_KEYBYTES      32
#define COSE_CRYPTO_AEAD_AESCCM_16_128_256_NONCEBYTES    13
#define COSE_CRYPTO_AEAD_AESCCM_16_128_256_ABYTES        16

#define COSE_CRYPTO_AEAD_AESCCM_64_128_256_KEYBYTES      32
#define COSE_CRYPTO_AEAD_AESCCM_64_128_256_NONCEBYTES    7
#define COSE_CRYPTO_AEAD_AESCCM_64_128_256_ABYTES        16

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COSE_CRYPTO_H */

/** @} */
