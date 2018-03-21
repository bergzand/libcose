/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and NaCL implementations
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <crypto_sign.h>
#include "cose.h"
#include "cose/crypto.h"

static uint8_t crypt_sign_scratch[COSE_MSGSIZE_MAX+crypto_sign_BYTES];
static uint8_t crypt_sign_verify_scratch[COSE_MSGSIZE_MAX];

void cose_crypto_sign(uint8_t *sign, unsigned long long int *signlen, uint8_t *msg, unsigned long long int msglen, uint8_t *skey)
{
    unsigned long long int slen = 0;
    memset(crypt_sign_scratch, 0, sizeof(crypt_sign_scratch));
    crypto_sign(crypt_sign_scratch, &slen, msg, msglen, (unsigned char *)skey);
    memcpy(sign, crypt_sign_scratch, crypto_sign_BYTES);
    *signlen = slen - msglen;
}

int cose_crypto_verify(uint8_t *sign, uint8_t *msg, uint64_t msglen,  uint8_t *pkey)
{
    unsigned long long int mlen = 0;
    memset(crypt_sign_scratch, 0, sizeof(crypt_sign_scratch));
    memset(crypt_sign_verify_scratch, 0, sizeof(crypt_sign_verify_scratch));
    memcpy(crypt_sign_scratch, sign, crypto_sign_BYTES);
    memcpy(crypt_sign_scratch + crypto_sign_BYTES, msg, msglen);
    int res = crypto_sign_open(crypt_sign_verify_scratch, &mlen, crypt_sign_scratch, crypto_sign_BYTES+msglen, pkey);
    return res;
}

void cose_crypto_keypair(uint8_t *pk, uint8_t *sk)
{
    crypto_sign_keypair(pk, sk);
}
