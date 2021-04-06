/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cose/crypto.h"
#include "cose/sign.h"
#include "cose_defines.h"

#include "cose/test.h"

#include "CUnit/CUnit.h"
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"

static char kid[] = "koen@example.org";
static char kid2[] = "koen@example.net";

#ifdef HAVE_ALGO_EDDSA
#define TEST_CRYPTO_SIGN_PUBLICKEYBYTES COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES
#define TEST_CRYPTO_SIGN_SECRETKEYBYTES COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES
#elif defined(HAVE_ALGO_ECDSA)
#define TEST_CRYPTO_SIGN_PUBLICKEYBYTES COSE_CRYPTO_SIGN_P521_PUBLICKEYBYTES
#define TEST_CRYPTO_SIGN_SECRETKEYBYTES COSE_CRYPTO_SIGN_P521_SECRETKEYBYTES
#endif

static unsigned char pkx1[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char pky1[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char sk1[TEST_CRYPTO_SIGN_SECRETKEYBYTES];
static unsigned char pkx2[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char pky2[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char sk2[TEST_CRYPTO_SIGN_SECRETKEYBYTES];

#define NUM_TESTS (sizeof(tests)/sizeof(struct test))
static uint8_t buf[2048];
static uint8_t ver_buf[2048];

static void genkey(cose_key_t *key, uint8_t *pkx, uint8_t *pky, uint8_t *sk)
{
    cose_key_init(key);
    #ifdef HAVE_ALGO_EDDSA
    cose_key_set_keys(key, COSE_EC_CURVE_ED25519, COSE_ALGO_EDDSA, pkx, pky, sk);
    cose_crypto_keypair_ed25519(key);
    #elif defined(HAVE_ALGO_ECDSA)
    cose_key_set_keys(key, COSE_EC_CURVE_P521, COSE_ALGO_ES512, pkx, pky, sk);
    cose_crypto_keypair_ecdsa(key, COSE_EC_CURVE_P521);
    #endif
}

static void print_bytestr(const uint8_t *bytes, size_t len)
{
    for(unsigned int idx=0; idx < len; idx++)
    {
        printf("%02X", bytes[idx]);
    }
}

/* Tagged 1 signer test */
void test_sign1(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_enc_t sign;
    cose_signature_t signature;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_signature_init(&signature);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signature, &key);

    /* Encode COSE sign object */
    COSE_ssize_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign);

    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);
    printf("Encode size: %ld\n", encode_size);
    print_bytestr(psign, encode_size);


    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);

    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
}

/* Untagged 1 signer test */
void test_sign2(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_enc_t sign;
    cose_signature_t signature;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, COSE_FLAGS_UNTAGGED);
    cose_signature_init(&signature);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    cose_sign_add_signer(&sign, &signature, &key);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign);

    CU_ASSERT_NOT_EQUAL(encode_size, 0);

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));

    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
}

void test_sign3(void)
{
    uint8_t *psign = NULL;
    char payload[] = "Input string";
    cose_sign_enc_t sign;
    cose_signature_t signature1, signature2;
    cose_key_t key, key2;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_signature_init(&signature1);
    cose_signature_init(&signature2);

    /* Add payload */
    cose_sign_set_payload(&sign, payload, strlen(payload));

    /* First signer */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    /* Second signer */
    genkey(&key2, pkx2, pky2, sk2);
    cose_key_set_kid(&key2, (uint8_t*)kid2, sizeof(kid2) - 1);
    cose_sign_add_signer(&sign, &signature1, &key);
    cose_sign_add_signer(&sign, &signature2, &key2);

    size_t len = cose_sign_encode(&sign, buf, sizeof(buf), &psign);

    print_bytestr(psign, len);
    printf("\n");

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, psign, len), 0);

    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    /* Test correct signature with correct signer */
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key,ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
    /* Modify payload */
    ((int*)verify.payload)[0]++;
    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
}

/* Tagged 1 signer test */
void test_sign4(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_enc_t sign;
    cose_signature_t signature;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_signature_init(&signature);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signature, &key);
    /* Octet stream content type */

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign);

    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    /* Verify with signature slot 0 */
    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
}

/* External payload signer test */
void test_sign5(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_enc_t sign;
    cose_signature_t signature;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, COSE_FLAGS_EXTDATA);
    cose_signature_init(&signature);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    cose_sign_add_signer(&sign, &signature, &key);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign);
    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    CU_ASSERT(verify.flags & COSE_FLAGS_EXTDATA);
    CU_ASSERT_EQUAL(verify.payload_len, 0);
    CU_ASSERT_EQUAL(verify.payload, NULL);
    cose_sign_decode_set_payload(&verify, sign1_payload, strlen(sign1_payload));

    /* Verify with signature slot 0 */
    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
}

/* External payload signer test */
void test_sign6(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_enc_t sign;
    cose_signature_t signature;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_signature_init(&signature);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First key */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    cose_sign_add_signer(&sign, &signature, &key);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign);
    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
}

void test_sign7(void)
{
    uint8_t *psign = NULL;
    char payload[] = "Input string";
    cose_sign_enc_t sign;
    cose_signature_t signature1, signature2;
    cose_key_t key, key2;
    cose_hdr_t hdr42, hdr41, hdr45, hdr47;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_signature_init(&signature1);
    cose_signature_init(&signature2);

    /* Add payload */
    cose_sign_set_payload(&sign, payload, strlen(payload));

    /* First key */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    /* Second signer */
    genkey(&key2, pkx2, pky2, sk2);
    cose_key_set_kid(&key2, (uint8_t*)kid2, sizeof(kid2) - 1);

    cose_sign_add_signer(&sign, &signature1, &key);
    cose_hdr_format_int(&hdr42, 42, 3);
    cose_signature_insert_prot(&signature1, &hdr42);
    cose_hdr_format_int(&hdr41, 41, 7);
    cose_signature_insert_unprot(&signature1, &hdr41);

    cose_sign_add_signer(&sign, &signature2, &key2);
    cose_hdr_format_int(&hdr45, 45, -2);
    cose_signature_insert_prot(&signature2, &hdr45);
    cose_hdr_format_int(&hdr47, 47, -3);
    cose_signature_insert_unprot(&signature2, &hdr47);

    size_t len = cose_sign_encode(&sign, buf, sizeof(buf), &psign);
    printf("\n");
    print_bytestr(psign, len);
    printf("\n");

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, psign, len), 0);

    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));

    cose_hdr_t hdr;
    CU_ASSERT_EQUAL(cose_signature_decode_protected(&vsignature, &hdr, 45), COSE_OK);
    CU_ASSERT_EQUAL(hdr.v.value, -2);

    CU_ASSERT_EQUAL(cose_signature_decode_unprotected(&vsignature, &hdr, 47), COSE_OK);
    CU_ASSERT_EQUAL(hdr.v.value, -3);

    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);

    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));
    CU_ASSERT_EQUAL_FATAL(cose_signature_decode_protected(&vsignature, &hdr, 42), COSE_OK);
    CU_ASSERT_EQUAL(hdr.v.value, 3);

    CU_ASSERT_EQUAL_FATAL(cose_signature_decode_unprotected(&vsignature, &hdr, 41), COSE_OK);
    CU_ASSERT_EQUAL(hdr.v.value, 7);
    /* Test correct signature with correct key */
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);

    CU_ASSERT_FALSE(cose_sign_signature_iter(&verify, &vsignature));
}

/* AAD test */
void test_sign8(void)
{
    uint8_t *psign = NULL;
    char sign_payload[] = "Input string";
    char sign_aad[] = "Additional data to be authenticated";
    memset(buf, 0, sizeof(buf));
    cose_sign_enc_t sign;
    cose_signature_t signature;
    cose_key_t key;

    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_signature_init(&signature);

    /* Add payload */
    cose_sign_set_payload(&sign, sign_payload, strlen(sign_payload));

    /* First signer */
    genkey(&key, pkx1, pky1, sk1);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signature, &key);
    /* Octet stream content type */

    /* Encode COSE sign object */
    ssize_t size_no_aad = cose_sign_encode(&sign, buf, sizeof(buf), &psign);

    CU_ASSERT_NOT_EQUAL_FATAL(size_no_aad, 0);

    cose_sign_set_external_aad(&sign, sign_aad, strlen(sign_aad));

    ssize_t size_w_aad = cose_sign_encode(&sign, buf, sizeof(buf), &psign);

    if (key.algo != COSE_ALGO_ES512) {
        /* ECDSA signatures have variable lengths, no sense in checking this */
        CU_ASSERT_EQUAL(size_w_aad, size_no_aad);
    }

    cose_sign_dec_t verify;
    cose_signature_dec_t vsignature;

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, size_w_aad);
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);


    /* Verify with signature slot 0 */
    cose_sign_signature_iter_init(&vsignature);
    CU_ASSERT(cose_sign_signature_iter(&verify, &vsignature));

    /* Must fail without aad */
    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_NOT_EQUAL(verification, COSE_OK);

    cose_sign_decode_set_external_aad(&verify, sign_aad, strlen(sign_aad));

    /* Must succeed with aad */
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, COSE_OK);

    sign_aad[0] ^= 0x01;

    /* Must fail with wrong aad */
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_NOT_EQUAL(verification, COSE_OK);
}

const test_t tests_sign[] = {
    {
        .f = test_sign1,
        .n = "Sign with 1 sig",
    },
    {
        .f = test_sign2,
        .n = "Sign with 1 sig untagged",
    },
    {
        .f = test_sign3,
        .n = "Sign with two sigs",
    },
    {
        .f = test_sign4,
        .n = "Content type header test",
    },
    {
        .f = test_sign5,
        .n = "External payload header test",
    },
    {
        .f = test_sign6,
        .n = "Sign1 Sig headers test",
    },
    {
        .f = test_sign7,
        .n = "Sign Sig headers test",
    },
    {
        .f = test_sign8,
        .n = "Sign with aad test",
    },
    {
        .f = NULL,
        .n = NULL,
    }
};
