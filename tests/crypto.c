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

static const uint8_t key_1[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

static const uint8_t msg_1[] = {
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e
};

static const uint8_t aad_1[] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
};

static const uint8_t nonce_1[] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};

static const uint8_t ciphertext_1[] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
    0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
};

void test_crypto_chacha_vector(void)
{
    unsigned char ciphertext[sizeof(msg_1) + COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES];
    unsigned char plaintext[sizeof(msg_1)];

    size_t cipherlen = 0;
    size_t msglen = 0;
    /* Generate key */
    cose_crypto_aead_encrypt_chachapoly(ciphertext, &cipherlen, (unsigned char *)msg_1, sizeof(msg_1), (unsigned char *)aad_1, sizeof(aad_1), nonce_1, key_1);
    CU_ASSERT_EQUAL(memcmp(ciphertext, ciphertext_1, sizeof(ciphertext_1)), 0);
    CU_ASSERT_EQUAL(sizeof(ciphertext_1), cipherlen);
    CU_ASSERT_EQUAL(
        cose_crypto_aead_decrypt_chachapoly(plaintext, &msglen, ciphertext, cipherlen, aad_1, sizeof(aad_1), nonce_1, key_1),
        0 );
    CU_ASSERT_EQUAL(msglen, sizeof(msg_1));
    CU_ASSERT_EQUAL(memcmp(msg_1, plaintext, sizeof(msg_1)), 0);
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
    {
        .f = test_crypto_chacha_vector,
        .n = "AEAD Chacha20poly1305 encrypt/decrypt with IETF test vector",
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
