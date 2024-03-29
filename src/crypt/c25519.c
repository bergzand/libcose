/*
 * Copyright (C) 2018 Koen Zandberg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and C25519
 */

#include <stdlib.h>
#include <stdint.h>
#include <edsign.h>
#include "cose_defines.h"
#include "cose/crypto.h"
#include "cose/crypto/c25519.h"
#include "cose/crypto/selectors.h"


extern cose_crypt_rng cose_crypt_get_random;
extern void *cose_crypt_rng_arg;

#ifdef CRYPTO_C25519_INCLUDE_ED25519
int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen)
{
    *signlen = EDSIGN_SIGNATURE_SIZE;
    edsign_sign(sign, key->x,
		 key->d, msg, msglen);
    return COSE_OK;
}

int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen)
{
    (void)signlen;
    return  edsign_verify(sign, key->x, msg, msglen) ? 0 : -1;

}

void cose_crypto_keypair_ed25519(cose_key_t *key)
{
    cose_crypt_get_random(cose_crypt_rng_arg, key->d, EDSIGN_SECRET_KEY_SIZE);
    edsign_sec_to_pub(key->x, key->d);
}
#endif /* CRYPTO_C25519_INCLUDE_ED25519 */
