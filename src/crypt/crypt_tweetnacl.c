/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Glue layer between libcose and tweetNaCL
 * TODO: no huge buffers :)
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <tweetnacl.h>
#include <sys/random.h>
#include "cose.h"
#include "cose/crypto.h"

static uint8_t sign_buf[2048];
static uint8_t verify_buf[2048];

void cose_crypto_sign_ed25519(uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen, uint8_t *skey)
{

    unsigned long long int signature_len = 0;

    crypto_sign(sign_buf, &signature_len, msg, msglen, (unsigned char *)skey);
    memcpy(sign, sign_buf, crypto_sign_BYTES);
    *signlen = (size_t)crypto_sign_BYTES;
}

int cose_crypto_verify_ed25519(const uint8_t *sign, uint8_t *msg, uint64_t msglen,  uint8_t *pkey)
{
    unsigned long long mlen;
    memcpy(sign_buf, sign, crypto_sign_BYTES);
    memcpy(sign_buf + crypto_sign_BYTES, msg, msglen);
    return crypto_sign_open(verify_buf, &mlen, sign_buf, crypto_sign_BYTES + msglen, pkey);
}

void cose_crypto_keypair_ed25519(uint8_t *pk, uint8_t *sk)
{
    crypto_sign_keypair(pk, sk);
}

size_t cose_crypto_sig_size_ed25519(void)
{
    return crypto_sign_BYTES;
}

void randombytes(uint8_t *target, uint64_t n)
{
    getrandom(target, n, 0);
}
