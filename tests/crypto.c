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
#include "cose/intern.h"
#include "cose/test.h"
#include <CUnit/CUnit.h>

#ifdef HAVE_ALGO_EDDSA
void test_crypto1(void)
{
    const uint8_t payload[] = "Input string";
    uint8_t pk[COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
    uint8_t sk[COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES];
    unsigned char signature[COSE_CRYPTO_SIGN_ED25519_SIGNBYTES];

    size_t signaturelen = 0;
    cose_key_t key;
    key.d = sk;
    key.x = pk;
    cose_crypto_keypair_ed25519(&key);

    cose_crypto_sign_ed25519(&key, signature, &signaturelen, (uint8_t*)payload, sizeof(payload));
    int res = cose_crypto_verify_ed25519(&key, signature, signaturelen, (uint8_t*)payload, sizeof(payload));
    printf("Sig size %lu\n", signaturelen);
    CU_ASSERT_EQUAL(res, 0);
}
#endif

#ifdef HAVE_ALGO_CHACHA20POLY1305
void test_crypto2(void)
{
    uint8_t payload[] = "Input string";
    uint8_t additional_data[] = "Extra signed data";
    uint8_t aead_sk[COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES];
    uint8_t nonce[COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES] = { 0 };
    unsigned char ciphertext[sizeof(payload) + COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES];
    unsigned char plaintext[sizeof(payload)];

    /* Generate key */
    size_t cipherlen;
    size_t msglen = 0;
    cose_crypto_keygen(aead_sk, sizeof(aead_sk), COSE_ALGO_CHACHA20POLY1305);
    cose_crypto_aead_encrypt_chachapoly(ciphertext, &cipherlen, (unsigned char *)payload, sizeof(payload), (unsigned char *)additional_data, sizeof(additional_data), nonce, aead_sk);
    CU_ASSERT_EQUAL(
        cose_crypto_aead_decrypt_chachapoly(plaintext, &msglen, ciphertext, cipherlen, additional_data, sizeof(additional_data), nonce, aead_sk),
        0 );
    CU_ASSERT_EQUAL(msglen, sizeof(payload));
    CU_ASSERT_EQUAL(memcmp(payload, plaintext, sizeof(payload)), 0);
}
#endif

#ifdef HAVE_ALGO_AES128GCM
void test_crypto_aes128(void)
{
    uint8_t payload[] = "Input string";
    uint8_t additional_data[] = "Extra signed data";
    uint8_t sk[COSE_CRYPTO_AEAD_AES128GCM_KEYBYTES];
    uint8_t nonce[COSE_CRYPTO_AEAD_AES128GCM_NONCEBYTES] = { 0 };
    unsigned char ciphertext[sizeof(payload) + COSE_CRYPTO_AEAD_AES128GCM_ABYTES];
    unsigned char plaintext[sizeof(payload)];
    /* Generate key */
    size_t cipherlen;
    size_t msglen = 0;
    CU_ASSERT_EQUAL(cose_crypto_keygen(sk, sizeof(sk), COSE_ALGO_A128GCM), COSE_CRYPTO_AEAD_AES128GCM_KEYBYTES);
    printf("Key:\n");
    print_bytestr(sk, sizeof(sk));
    printf("\n");
    CU_ASSERT_EQUAL(cose_crypto_aead_encrypt_aesgcm(ciphertext, &cipherlen, (unsigned char *)payload, sizeof(payload), (unsigned char *)additional_data, sizeof(additional_data), nonce, sk, COSE_CRYPTO_AEAD_AES128GCM_KEYBYTES), 0);
    CU_ASSERT_EQUAL(
        cose_crypto_aead_decrypt_aesgcm(plaintext, &msglen, ciphertext, cipherlen, additional_data, sizeof(additional_data), nonce, sk, COSE_CRYPTO_AEAD_AES128GCM_KEYBYTES),
        0 );
    CU_ASSERT_EQUAL(msglen, sizeof(payload));
    CU_ASSERT_EQUAL(memcmp(payload, plaintext, sizeof(payload)), 0);
}
#endif
#ifdef HAVE_ALGO_AES192GCM
void test_crypto_aes192(void)
{
    uint8_t payload[] = "Input string";
    uint8_t additional_data[] = "Extra signed data";
    uint8_t sk[COSE_CRYPTO_AEAD_AES192GCM_KEYBYTES];
    uint8_t nonce[COSE_CRYPTO_AEAD_AES192GCM_NONCEBYTES] = { 0 };
    unsigned char ciphertext[sizeof(payload) + COSE_CRYPTO_AEAD_AES192GCM_ABYTES];
    unsigned char plaintext[sizeof(payload)];
    /* Generate key */
    size_t cipherlen;
    size_t msglen = 0;
    CU_ASSERT_EQUAL(cose_crypto_keygen(sk, sizeof(sk), COSE_ALGO_A192GCM), COSE_CRYPTO_AEAD_AES192GCM_KEYBYTES);
    printf("Key:\n");
    print_bytestr(sk, sizeof(sk));
    printf("\n");
    CU_ASSERT_EQUAL(cose_crypto_aead_encrypt_aesgcm(ciphertext, &cipherlen, (unsigned char *)payload, sizeof(payload), (unsigned char *)additional_data, sizeof(additional_data), nonce, sk, COSE_CRYPTO_AEAD_AES192GCM_KEYBYTES), 0);
    CU_ASSERT_EQUAL(
        cose_crypto_aead_decrypt_aesgcm(plaintext, &msglen, ciphertext, cipherlen, additional_data, sizeof(additional_data), nonce, sk, COSE_CRYPTO_AEAD_AES192GCM_KEYBYTES),
        0 );
    CU_ASSERT_EQUAL(msglen, sizeof(payload));
    CU_ASSERT_EQUAL(memcmp(payload, plaintext, sizeof(payload)), 0);
}
#endif
#ifdef HAVE_ALGO_AES256GCM
void test_crypto_aes256(void)
{
    uint8_t payload[] = "Input string";
    uint8_t additional_data[] = "Extra signed data";
    uint8_t sk[COSE_CRYPTO_AEAD_AES256GCM_KEYBYTES];
    uint8_t nonce[COSE_CRYPTO_AEAD_AES256GCM_NONCEBYTES] = { 0 };
    unsigned char ciphertext[sizeof(payload) + COSE_CRYPTO_AEAD_AES256GCM_ABYTES];
    unsigned char plaintext[sizeof(payload)];
    /* Generate key */
    size_t cipherlen;
    size_t msglen = 0;
    CU_ASSERT_EQUAL(cose_crypto_keygen(sk, sizeof(sk), COSE_ALGO_A256GCM), COSE_CRYPTO_AEAD_AES256GCM_KEYBYTES);
    printf("Key:\n");
    print_bytestr(sk, sizeof(sk));
    printf("\n");
    CU_ASSERT_EQUAL(cose_crypto_aead_encrypt_aesgcm(ciphertext, &cipherlen, (unsigned char *)payload, sizeof(payload), (unsigned char *)additional_data, sizeof(additional_data), nonce, sk, COSE_CRYPTO_AEAD_AES256GCM_KEYBYTES), 0);
    CU_ASSERT_EQUAL(
        cose_crypto_aead_decrypt_aesgcm(plaintext, &msglen, ciphertext, cipherlen, additional_data, sizeof(additional_data), nonce, sk, COSE_CRYPTO_AEAD_AES256GCM_KEYBYTES),
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
        .n = "AEAD Chacha20poly1305 encrypt/decrypt",
    },
#endif
#ifdef HAVE_ALGO_AES128GCM
    {
        .f = test_crypto_aes128,
        .n = "AEAD aes128gcm encrypt/decrypt",
    },
#endif
#ifdef HAVE_ALGO_AES192GCM
    {
        .f = test_crypto_aes192,
        .n = "AEAD aes192gcm encrypt/decrypt",
    },
#endif
#ifdef HAVE_ALGO_AES256GCM
    {
        .f = test_crypto_aes256,
        .n = "AEAD aes256gcm encrypt/decrypt",
    },
#endif
    {
        .f = NULL,
        .n = NULL,
    }
};
