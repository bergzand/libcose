/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and libsodium
 */

#include "cose.h"
#include "cose/crypto.h"
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_sign.h>
#include <stdint.h>
#include <stdlib.h>

int cose_crypto_aead_encrypt_chachapoly(uint8_t *c,
                                        size_t *clen,
                                        const uint8_t *msg,
                                        size_t msglen,
                                        const uint8_t *aad,
                                        size_t aadlen,
                                        const uint8_t *npub,
                                        const uint8_t *k)
{
    unsigned long long cipherlen = 0;
    int res = crypto_aead_chacha20poly1305_ietf_encrypt((unsigned char*)c, &cipherlen, (const unsigned char*)msg, msglen, (const unsigned char *)aad, aadlen, NULL, (const unsigned char*)npub, (const unsigned char*)k);
    *clen = cipherlen;
    return res;
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
    unsigned long long messagelen = 0;
    int res = crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char *)msg,
            &messagelen,
            NULL,
            (const unsigned char*)c,
            clen,
            (const unsigned char *)aad,
            aadlen,
            (const unsigned char*)npub,
            (const unsigned char *)k);
    *msglen = messagelen;
    return res;
}

size_t cose_crypto_aead_keypair_chachapoly(uint8_t *sk, size_t len)
{
    if (len < crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        return 0;
    }
    crypto_aead_chacha20poly1305_ietf_keygen((unsigned char*)sk);
    return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
}

size_t cose_crypto_aead_nonce_chachapoly(uint8_t *nonce, size_t len)
{
    if (len < crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        return 0;
    }
    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    return crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
}


void cose_crypto_sign_ed25519(uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen, uint8_t *skey)
{
    unsigned long long int signature_len = 0;

    crypto_sign_detached(sign, &signature_len, msg, msglen, (unsigned char *)skey);
    *signlen = (size_t)signature_len;
}

int cose_crypto_verify_ed25519(const uint8_t *sign, uint8_t *msg, uint64_t msglen,  uint8_t *pkey)
{
    return crypto_sign_verify_detached(sign, msg, msglen, pkey);
}

void cose_crypto_keypair_ed25519(uint8_t *pk, uint8_t *sk)
{
    crypto_sign_keypair(pk, sk);
}

size_t cose_crypto_sig_size_ed25519(void)
{
    return crypto_sign_BYTES;
}
