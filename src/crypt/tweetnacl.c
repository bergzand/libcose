/*
 * Copyright (C) 2018 Freie Universitat Berlin
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
#include <stdint.h>
#include <string.h>
#include <tweetnacl.h>
#include "cose_defines.h"
#include "cose/crypto.h"

static uint8_t msg_buf[2048];
static uint8_t verify_buf[2048];

int cose_crypto_sign_ed25519(const cose_key_t *key, uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen)
{
    unsigned long long int signature_len = 0;

    crypto_sign(sign, &signature_len, msg, msglen, (unsigned char *)key->d);
    *signlen = (size_t)crypto_sign_BYTES;
    return COSE_OK;
}

int cose_crypto_verify_ed25519(const cose_key_t *key, const uint8_t *sign, size_t signlen, uint8_t *msg, uint64_t msglen)
{
    (void)signlen;
    unsigned long long mlen;

    memcpy(verify_buf + crypto_sign_BYTES, msg, msglen);
    memcpy(verify_buf, sign, crypto_sign_BYTES);
    return crypto_sign_open(msg_buf, &mlen, verify_buf, crypto_sign_BYTES + msglen, key->x);
}

void cose_crypto_keypair_ed25519(cose_key_t *key)
{
    crypto_sign_keypair(key->x, key->d);
}

size_t cose_crypto_sig_size_ed25519(void)
{
    return crypto_sign_BYTES;
}

