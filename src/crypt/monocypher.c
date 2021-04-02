/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and Monocypher
 */


#include <stdlib.h>
#include <stdint.h>
#include <monocypher.h>
#include <optional/monocypher-ed25519.h>
#include "cose/crypto.h"
#include "cose/crypto/selectors.h"

extern void randombytes(uint8_t *target, uint64_t n);
static const uint8_t zero[32] = { 0 };

#ifdef CRYPTO_MONOCYPHER_INCLUDE_CHACHAPOLY
static size_t _align(size_t x, size_t pow2)
{
    return (~x + 1) & (pow2 - 1);
}

int cose_crypto_aead_encrypt_chachapoly(uint8_t *c,
                                        size_t *clen,
                                        const uint8_t *msg,
                                        size_t msglen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k)
{
    uint8_t auth_key[32];
    crypto_poly1305_ctx poly;
    /* Use block 0 for the poly1305 one-time key */
    crypto_ietf_chacha20_ctr(auth_key, zero, sizeof(auth_key),
                             k, npub, 0);
    crypto_ietf_chacha20_ctr(c, msg, msglen, k, npub, 1);

    crypto_poly1305_init(&poly, auth_key);
    crypto_poly1305_update(&poly, aad, aadlen);
    crypto_poly1305_update(&poly, zero, _align(aadlen, 16));
    crypto_poly1305_update(&poly, c, msglen);
    crypto_poly1305_update(&poly, zero, _align(msglen, 16));

    uint64_t poly_aad_len = aadlen;
    uint64_t poly_cipher_len = msglen;

    crypto_poly1305_update(&poly, (uint8_t*)&poly_aad_len, sizeof(poly_aad_len));
    crypto_poly1305_update(&poly, (uint8_t*)&poly_cipher_len, sizeof(poly_cipher_len));
    crypto_poly1305_final(&poly, c + msglen);
    *clen = msglen + 16;
    crypto_wipe(auth_key, sizeof(auth_key));
    return COSE_OK;
}

int cose_crypto_aead_decrypt_chachapoly(uint8_t *msg,
                                        size_t *msglen,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k)
{
    uint8_t auth_key[32];
    uint8_t mac[16];
    crypto_poly1305_ctx poly;
    int res = COSE_OK;

    *msglen = clen - 16;

    /* Use block 0 for the poly1305 one-time key */
    crypto_ietf_chacha20_ctr(auth_key, zero, sizeof(auth_key),
                             k, npub, 0);
    crypto_poly1305_init(&poly, auth_key);
    crypto_poly1305_update(&poly, aad, aadlen);
    crypto_poly1305_update(&poly, zero, _align(aadlen, 16));
    crypto_poly1305_update(&poly, c, *msglen);
    crypto_poly1305_update(&poly, zero, _align(*msglen, 16));

    uint64_t poly_aad_len = aadlen;
    uint64_t poly_cipher_len = *msglen;

    crypto_poly1305_update(&poly, (uint8_t*)&poly_aad_len, sizeof(poly_aad_len));
    crypto_poly1305_update(&poly, (uint8_t*)&poly_cipher_len, sizeof(poly_cipher_len));
    crypto_poly1305_final(&poly, mac);

    if (crypto_verify16(mac, c + *msglen)) {
        res = COSE_ERR_CRYPTO;
    }
    else {
        crypto_ietf_chacha20_ctr(msg, c, *msglen, k, npub, 1);
    }
    crypto_wipe(mac, sizeof(mac));
    crypto_wipe(auth_key, sizeof(auth_key));
    return res;
}

COSE_ssize_t cose_crypto_keygen_chachapoly(uint8_t *sk, size_t len)
{
    if (len < 64) {
        return COSE_ERR_NOMEM;
    }
    randombytes((unsigned char*)sk, 64);
    return 64;
}
#endif /* CRYPTO_MONOCYPHER_INCLUDE_CHACHAPOLY */

#ifdef CRYPTO_MONOCYPHER_INCLUDE_ED25519
int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen)
{
    *signlen = cose_crypto_sig_size_ed25519();
    crypto_ed25519_sign(sign, key->d, key->x, msg, msglen);
    return COSE_OK;
}

int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen)
{
    (void)signlen;
    return crypto_ed25519_check(sign, key->x, msg, msglen) == 0 ? COSE_OK : COSE_ERR_CRYPTO;
}

static void _ed25519_clamp(uint8_t *key)
{
    key[0] &= 0xf8;
    key[31] &= 0x7f;
    key[31] |= 0x40;
}

void cose_crypto_keypair_ed25519(cose_key_t *key)
{
    randombytes(key->d, COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES);
    _ed25519_clamp(key->d);
    crypto_sign_public_key(key->x, key->d);
}

size_t cose_crypto_sig_size_ed25519(void)
{
    return 64;
}
#endif /* CRYPTO_MONOCYPHER_INCLUDE_ED25519 */
