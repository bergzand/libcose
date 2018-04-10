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
#include <unistd.h>

#ifdef CRYPTO_SODIUM
#include "cose/crypto/sodium.h"
#include <sodium.h>
#elif defined(CRYPTO_TWEETNACL)
#include "cose/crypto/tweetnacl.h"
#include <tweetnacl.h>
#endif

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
ssize_t cose_crypto_keygen(uint8_t *buf, size_t len, cose_algo_t algo);

/**
 * @name crypto AEAD functions
 * @{
 */
/**
 * Generic AEAD function, key must match sizes of selected algo
 */
int cose_crypto_aead(uint8_t *c, size_t *clen, const uint8_t *msg, size_t msglen, const uint8_t *aad, size_t aadlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *key, cose_algo_t algo);

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

/**
 * Generate a symmetric key for AEAD operations
 */
size_t cose_crypto_aead_keypair_chachapoly(uint8_t *sk, size_t len);
size_t cose_crypto_aead_nonce_chachapoly(uint8_t *nonce, size_t len);
ssize_t cose_crypto_aead_nonce_size(cose_algo_t algo);

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
 * Sign a byte string with an ed25519 private key
 *
 * @param[out]  sign    The resulting signature
 * @param[out]  signlen The length of the signature
 * @param       msg     The message to sign
 * @param       msglen  The length of the message
 * @param       skey    The secret key to sign with
 */
int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen);


/**
 * Verify a byte string and signature with an ed25519 public key
 *
 * @param[out]  sign    The signature
 * @param       msg     The message to verify
 * @param       msglen  The length of the message
 * @param       pkey    The public key to verify with
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

/**
 * Get the size of an ed25519 signature
 *
 * @return      Signature size
 */
size_t cose_crypto_sig_size_ed25519(void);
/** @} */

#endif /* COSE_CRYPTO_H */

/** @} */
