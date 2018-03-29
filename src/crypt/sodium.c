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

int cose_crypto_aead_encrypt_chachapoly(unsigned char *c,
                                        unsigned char *mac,
                                        unsigned long long *maclen_p,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *ad,
                                        unsigned long long adlen,
                                        const unsigned char *npub,
                                        const unsigned char *k)
{
    return crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, NULL, npub, k);
}

int cose_crypto_aead_decrypt_chachapoly(unsigned char *m,
                                        const unsigned char *c,
                                        unsigned long long clen,
                                        const unsigned char *mac,
                                        const unsigned char *ad,
                                        unsigned long long adlen,
                                        const unsigned char *npub,
                                        const unsigned char *k)
{
    return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, NULL, c, clen, mac, ad, adlen, npub, k);
}

void cose_crypto_aead_keypair_chachapoly(uint8_t *sk)
{
    crypto_aead_xchacha20poly1305_ietf_keygen((unsigned char*)sk);
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
