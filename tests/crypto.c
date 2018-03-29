/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include "cose/crypto.h"
#include "cose/test.h"
#include <CUnit/CUnit.h>

static char payload[] = "Input string";
static char additional_data[] = "Extra signed data";
static unsigned char pk[crypto_sign_PUBLICKEYBYTES];
static unsigned char sk[crypto_sign_SECRETKEYBYTES];
static unsigned char aead_sk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
static unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

unsigned char ciphertext[sizeof(payload) + crypto_aead_xchacha20poly1305_ietf_ABYTES];


#define MLEN (sizeof(payload))
#define SMLEN (sizeof(payload)+ crypto_sign_BYTES)
static unsigned char signature[crypto_sign_BYTES];


void test_crypto1(void)
{
    size_t signaturelen = 0;
    cose_crypto_keypair_ed25519(pk, sk);

    cose_crypto_sign_ed25519(signature, &signaturelen, (uint8_t*)payload, MLEN, sk);
    int res = cose_crypto_verify_ed25519(signature, (uint8_t*)payload, MLEN, pk);
    CU_ASSERT_EQUAL(res, 0);
}

void test_crypto2(void)
{
    /* Generate key */
    cose_crypto_aead_keypair_chachapoly(aead_sk);
    (void)nonce;
    (void)additional_data;
}

const test_t tests_crypto[] = {
    {
        .f = test_crypto1,
        .n = "Simple sign and verify",
    },
    {
        .f = test_crypto2,
        .n = "Simple AEAD encrypt/decrypt",
    },
    {
        .f = NULL,
        .n = NULL,
    }
};
