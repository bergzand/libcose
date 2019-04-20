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
#include "cose/crypto.h"

extern void randombytes(uint8_t *target, uint64_t n);

static uint32_t load32_le(const uint8_t *u)
{
    return (uint32_t)u[0]
        | ((uint32_t)u[1] <<  8U)
        | ((uint32_t)u[2] << 16U)
        | ((uint32_t)u[3] << 24U);
}

static void _crypto_aead_chachapoly_init(crypto_lock_ctx *ctx,
                                         const uint8_t *npub, const uint8_t *k)
{
    /* Have to mess around a bit to get IETF style chacha20poly1305 here */
    uint8_t auth_key[64];

    ctx->ad_phase = 1;
    ctx->ad_size = 0;
    ctx->message_size = 0;

    /* Chacha20poly1305 initialization */
    crypto_chacha20_init(&ctx->chacha, k, npub);

	/* Fix IETF chacha20poly1305 mode */
    ctx->chacha.input[13] = load32_le(npub + 0);
    ctx->chacha.input[14] = load32_le(npub + 4);
    ctx->chacha.input[15] = load32_le(npub + 8);

    crypto_chacha20_stream(&ctx->chacha, auth_key, 64);
    crypto_poly1305_init(&ctx->poly, auth_key);
    crypto_wipe(auth_key, sizeof(auth_key));
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
    crypto_lock_ctx ctx;

    _crypto_aead_chachapoly_init(&ctx, npub, k);

    crypto_lock_auth_ad(&ctx, aad, aadlen);
    crypto_lock_update (&ctx, c, msg, msglen);
    crypto_lock_final  (&ctx, c + msglen);

    *clen = msglen + 16;
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
    crypto_unlock_ctx ctx;

    _crypto_aead_chachapoly_init(&ctx, npub, k);
    *msglen = clen - 16;

    crypto_unlock_auth_ad(&ctx, aad, aadlen);
    crypto_unlock_auth_message(&ctx, c, *msglen);
    crypto_chacha_ctx chacha_ctx = ctx.chacha;
    if (crypto_unlock_final(&ctx, c + *msglen)) {
        crypto_wipe(&chacha_ctx, sizeof(chacha_ctx));
        return COSE_ERR_CRYPTO;
    }
    crypto_chacha20_encrypt(&chacha_ctx, msg, c, *msglen);
    crypto_wipe(&chacha_ctx, sizeof(chacha_ctx));

    return COSE_OK;
}

COSE_ssize_t cose_crypto_keygen_chachapoly(uint8_t *sk, size_t len)
{
    if (len < 64) {
        return COSE_ERR_NOMEM;
    }
    randombytes((unsigned char*)sk, 64);
    return 64;
}

int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen)
{
    *signlen = cose_crypto_sig_size_ed25519();
    crypto_sign(sign, key->d, key->x, msg, msglen);
    return COSE_OK;
}

int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen)
{
    (void)signlen;
    return crypto_check(sign, key->x, msg, msglen) == 0 ? COSE_OK : COSE_ERR_CRYPTO;
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
