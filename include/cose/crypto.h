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

#include "cose/crypto/keysizes.h"
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
#if defined(CRYPTO_TINYCRYPT)
#include "cose/crypto/tinycrypt.h"
#endif
#if defined(CRYPTO_HASH_SIGS)
#include "cose/crypto/hash-sigs.h"
#endif

#include "cose/crypto/selectors.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief    Generic AEAD function, key must match sizes of selected algo
 *
 *
 * @param[out]      c       resulting ciphertext
 * @param[inout]    clen    length of the buffer, length of resulting ciphertext
 * @param           msg     message to encrypt
 * @param           msglen  length of the message
 * @param           aad     additional authenticated data to protect
 * @param           aadlen  length of the additional authenticated data
 * @param           key     key to decrypt with
 * @param           nonce   nonce to use
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
                                    cose_algo_t algo);

int cose_crypto_aead_decrypt_aesgcm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo);

int cose_crypto_aead_encrypt_aesccm(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo);

int cose_crypto_aead_decrypt_aesccm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    cose_algo_t algo);

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
/** @} */

/**
 * @name HKDF related functions
 * @{
 */

/**
 * @brief   Decide whether a given algorithm is known and an HKDF algorithm
 *
 * @param       alg         the algorithm to be checked
 *
 * @return      true if alg can be used with cose_crypto_hkdf_derive
 */
bool cose_crypto_is_hkdf(cose_algo_t alg);

/**
 * @brief    Derive a key using HKDF (HMAC based key derivation function)
 *
 * @param       salt        salt for key generation. Can be empty
 * @param       salt_len    salt length
 * @param       ikm         input key material
 * @param       ikm_length  input key material length
 * @param       info        info for derived key
 * @param       info_length info for derived key length
 * @param[out]  out         output buffer for derived key
 * @param       out_length  dervied key length
 * @param       alg         HKDF algorithm to use
 *
 * @return      COSE_OK on successful key derivations
 * @return      COSE_ERR_NOTIMPLEMENTED if the alg is unsupported
 * @return      COSE_ERR_INVALID_PARAM on invalid salt length
 * @return      COSE_ERR_CRYPTO otherwise
 */
int cose_crypto_hkdf_derive(const uint8_t *salt, size_t salt_len,
                            const uint8_t *ikm, size_t ikm_length,
                            const uint8_t *info, size_t info_length,
                            uint8_t *out, size_t out_length,
                            cose_algo_t alg);

/**
 * @brief   Derive a key using SHA256 HKDF (HMAC based key derivation function)
 *
 * @param       salt        salt for key generation. Can be empty
 * @param       salt_len    salt length
 * @param       ikm         input key material
 * @param       ikm_length  input key material length
 * @param       info        info for derived key
 * @param       info_length info for derived key length
 * @param[out]  out         output buffer for derived key
 * @param       out_length  dervied key length
 *
 * @return      COSE_OK on successful key derivations
 * @return      COSE_ERR_INVALID_PARAM on invalid salt length
 * @return      COSE_ERR_CRYPTO otherwise
 */
int cose_crypto_hkdf_derive_sha256(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *ikm, size_t ikm_length,
                                   const uint8_t *info, size_t info_length,
                                   uint8_t *out, size_t out_length);
/** @} */

int cose_crypto_keypair_hsslms(cose_key_t *key);
int cose_crypto_sign_hsslms(const cose_key_t *key, uint8_t *sig, size_t *siglen, uint8_t *msg, unsigned long long int msglen);
int cose_crypto_verify_hsslms(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen);
size_t cose_crypto_sig_size_hsslms(void);

#endif /* COSE_CRYPTO_H */

/** @} */
