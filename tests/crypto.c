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
#include "cose.h"
#include "cose/crypto.h"
#include "cose/test.h"
#include <CUnit/CUnit.h>

#if defined(HAVE_ALGO_EDDSA) || defined(HAVE_CRYPTO_CHACHA20POLY1305)
static uint8_t payload[] = "Input string";
#endif
#ifdef HAVE_ALGO_EDDSA
static uint8_t pk[COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
static uint8_t sk[COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES];
static unsigned char signature[crypto_sign_BYTES];
#endif

#ifdef HAVE_ALGO_CHACHA20POLY1305
static uint8_t additional_data[] = "Extra signed data";
static uint8_t aead_sk[COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
static uint8_t nonce[COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES] = { 0 };

unsigned char ciphertext[sizeof(payload) + COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES];
unsigned char plaintext[sizeof(payload)];
unsigned char tag[COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES];
#endif





#ifdef HAVE_ALGO_EDDSA
void test_crypto1(void)
{
    size_t signaturelen = 0;
    cose_key_t key;
    key.d = sk;
    key.x = pk;
    cose_crypto_keypair_ed25519(&key);

    cose_crypto_sign_ed25519(&key, signature, &signaturelen, (uint8_t*)payload, sizeof(payload));
    int res = cose_crypto_verify_ed25519(&key, signature, signaturelen, (uint8_t*)payload, sizeof(payload));
    CU_ASSERT_EQUAL(res, 0);
}
#endif

#ifdef HAVE_ALGO_CHACHA20POLY1305
void test_crypto2(void)
{
    /* Generate key */
    size_t cipherlen;
    size_t msglen = 0;
    cose_crypto_aead_keypair_chachapoly(aead_sk, sizeof(aead_sk));
    cose_crypto_aead_encrypt_chachapoly(ciphertext, &cipherlen, (unsigned char *)payload, sizeof(payload), (unsigned char *)additional_data, sizeof(additional_data), nonce, aead_sk);
    CU_ASSERT_EQUAL(
        cose_crypto_aead_decrypt_chachapoly(plaintext, &msglen, ciphertext, cipherlen, additional_data, sizeof(additional_data), nonce, aead_sk),
        0 );
    CU_ASSERT_EQUAL(msglen, sizeof(payload));
    CU_ASSERT_EQUAL(memcmp(payload, plaintext, sizeof(payload)), 0);
}
#endif

const test_t tests_crypto[] = {
#ifdef HAVE_ALGO_EDDSA
    {
        .f = test_crypto1,
        .n = "Simple sign and verify",
    },
#endif
#ifdef HAVE_ALGO_CHACHA20POLY1305
    {
        .f = test_crypto2,
        .n = "Simple AEAD encrypt/decrypt",
    },
#endif
    {
        .f = NULL,
        .n = NULL,
    }
};
