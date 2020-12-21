/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_crypto Crypto glue layer
 * @ingroup     cose
 *
 * Generic crypto function api for glueing purposes.
 * @{
 *
 * @file
 * @brief       API definitions for crypto operations
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_CRYPTO_H
#define COSE_CRYPTO_H

#include "cose/key.h"
#include "cose_defines.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef CRYPTO_SODIUM
#include "cose/crypto/sodium.h"
#endif
#if defined(CRYPTO_MONOCYPHER)
#include "cose/crypto/monocypher.h"
#endif
#if defined(CRYPTO_MBEDTLS)
#include "cose/crypto/mbedtls.h"
#endif
#if defined(CRYPTO_C25519)
#include "cose/crypto/c25519.h"
#endif
#if defined(CRYPTO_HACL)
#include "cose/crypto/hacl.h"
#endif
#if defined(CRYPTO_TINYDTLS)
#include "cose/crypto/tinydtls.h"
#endif

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

#define COSE_CRYPTO_AEAD_AESCCM_16_64_128_KEYBYTES     16
#define COSE_CRYPTO_AEAD_AESCCM_16_64_128_ABYTES       8
#define COSE_CRYPTO_AEAD_AESCCM_16_64_128_NONCEBYTES   13

/** @} */

typedef int (*cose_crypt_rng)(void *, unsigned char *, size_t);
void cose_crypt_set_rng(cose_crypt_rng f_rng, void *p_rng);

/**
 * Generated a key suitable for the requisted algo
 *
 * @param[out]      buf     Buffer to fill
 * @param           len     Size of the buffer
 * @param           algo    Algorithm to get the key for
 *
 * @return                  Size of the generated key
 * @return                  Negative on error
 */
COSE_ssize_t cose_crypto_keygen(uint8_t *buf, size_t len, cose_algo_t algo);

/**
 * @name crypto AEAD functions
 * @{
 */
/**
 * Generic AEAD function, key must match sizes of selected algo
 */
int cose_crypto_aead_encrypt(uint8_t *c, size_t *clen, const uint8_t *msg, size_t msglen, const uint8_t *aad, size_t aadlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *key, cose_algo_t algo);
int cose_crypto_aead_decrypt(uint8_t *msg,
                             size_t *msglen,
                             const uint8_t *c,
                             size_t clen,
                             const uint8_t *aad,
                             size_t aadlen,
                             const uint8_t *npub,
                             const uint8_t *k,
                             cose_algo_t algo);

bool cose_crypto_is_aead(cose_algo_t algo);

/**
 * Encrypt a byte array and sign a byte array with Chacha20-poly1305
 */
int cose_crypto_aead_encrypt_chachapoly(uint8_t *c,
                                        size_t *clen,
                                        const uint8_t *msg,
                                        size_t msglen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k);

/**
 * Verify a byte array and decrypt a byte array with Chacha20-poly1305
 */
int cose_crypto_aead_decrypt_chachapoly(uint8_t *msg,
                                        size_t *msglen,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k);


int cose_crypto_aead_encrypt_aesgcm(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize);

int cose_crypto_aead_decrypt_aesgcm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize);

int cose_crypto_aead_encrypt_aesccm(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize);

int cose_crypto_aead_decrypt_aesccm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize);

/**
 * Generate a symmetric key for AEAD operations
 */
COSE_ssize_t cose_crypto_keygen_chachapoly(uint8_t *sk, size_t len);
COSE_ssize_t cose_crypto_keygen_aesgcm(uint8_t *buf, size_t len, cose_algo_t algo);
size_t cose_crypto_aead_nonce_chachapoly(uint8_t *nonce, size_t len);
COSE_ssize_t cose_crypto_aead_nonce_size(cose_algo_t algo);

/** @} */

/**
 * @name Signing related functions
 *
 * @{
 */

int cose_crypto_sign(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen);
int cose_crypto_verify(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen);
size_t cose_crypto_sig_size(const cose_key_t *key);

/**
 * Sign a byte string with an ECDSA keypair
 *
 * @note This function can return COSE_ERR_NOTIMPLEMENTED when the specific
 * combination of hashing and curve is not available.
 */
int cose_crypto_sign_ecdsa(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg,  size_t msglen);
int cose_crypto_verify_ecdsa(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, size_t msglen);
size_t cose_crypto_sig_size_ecdsa(cose_curve_t curve);
/**
 * Sign a byte string with an ed25519 private key
 *
 * @param       key     The Key struct to sign with
 * @param[out]  sign    The resulting signature
 * @param[out]  signlen The length of the signature
 * @param       msg     The message to sign
 * @param       msglen  The length of the message
 */
int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen);


/**
 * Verify a byte string and signature with an ed25519 public key
 *
 * @param       key     The Key struct to verify with
 * @param[out]  sign    The signature
 * @param       signlen The signature length
 * @param       msg     The message to verify
 * @param       msglen  The length of the message
 *
 * @return              0 if verification succeeded
 */
int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen);

/**
 * generate an ed25519 keypair
 *
 * @param[out]  key  key struct to fill with generated keys
 *
 * @note key->x and key->d should provide large enough buffers for the key pair
 */
void cose_crypto_keypair_ed25519(cose_key_t *key);
void cose_crypto_keypair_ecdsa(cose_key_t *key, cose_curve_t curve);

/**
 * Get the size of an ed25519 signature
 *
 * @return      Signature size
 */
size_t cose_crypto_sig_size_ed25519(void);

/** @} */

/**
 * @name HKDF related functions
 *
 * @{
 */

/** @brief Decide whether a given algorithm is known and an HKDF algorithm
 *
 * @param[in]  alg The algorithm to be checked
 * @return     true iff @p alg can be used with @ref cose_crypto_hkdf_derive
 */
bool cose_crypto_is_hkdf(cose_algo_t alg);

/** @brief Derive a key using HKDF (HMAC based key derivation function)
 *
 * @param[in] salt Salt for key generation. Can be empty
 * @param[in] salt_len Length of @p salt
 * @param[in] ikm key material
 * @param[in] ikm_length Length of @p ikm
 * @param[in] info Info for for derived key
 * @param[in] info_length Length of @p info
 * @param[out] out Output buffer where the key is written to
 * @param[in] out_length Length of @p out
 * @param[in] alg HKDF algorithm to use
 */
int cose_crypto_hkdf_derive(const uint8_t *salt,
                            size_t salt_len,
                            const uint8_t *ikm,
                            size_t ikm_length,
                            const uint8_t *info,
                            size_t info_length,
                            uint8_t *out,
                            size_t out_length,
                            cose_algo_t alg);

/** @brief Derive a key using HMAC256
 *
 * @param[in] salt Salt for key generation. Can be empty
 * @param[in] salt_len Length of @p salt
 * @param[in] ikm key material
 * @param[in] ikm_length Length of @p ikm
 * @param[in] info Info for for derived key
 * @param[in] info_length Length of @p info
 * @param[out] out Output buffer where the key is written to
 * @param[in] out_length Length of @p out
 */
int cose_crypto_hkdf_derive_sha256(const uint8_t *salt,
                                   size_t salt_len,
                                   const uint8_t *ikm,
                                   size_t ikm_length,
                                   const uint8_t *info,
                                   size_t info_length,
                                   uint8_t *out,
                                   size_t out_length);
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COSE_CRYPTO_H */

/** @} */
