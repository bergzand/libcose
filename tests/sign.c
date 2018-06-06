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
    cose_sign_t sign, verify;
    cose_signature_t signature, vsignature;
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

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
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
    cose_sign_t sign, verify;
    cose_signature_t signature, vsignature;
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

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
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
    cose_sign_t sign, verify;
    cose_signature_t signature1, signature2, vsignature;
    cose_key_t key, key2;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_sign_init(&verify, 0);
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

    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, psign, len), 0);
    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
    /* Test correct signature with correct signer */
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key,ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
    /* Modify payload */
    ((int*)verify.payload)[0]++;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);
}

//void test_sign4(void)
//{
//    cose_key_t key;
//    genkey(&key, pkx1, pky1, sk1);
//    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
//    prev_len = 0;
//    uint8_t *psign = NULL;
//    for (unsigned i = 0; i <= 20; i++)
//    {
//        cur = 0;
//        max = 0;
//        total = 0;
//        cap_limit = i;
//        char sign1_payload[] = "Input string";
//        memset(buf, 0, sizeof(buf));
//        cose_sign_t sign;
//        /* Initialize struct */
//        cose_sign_init(&sign, 0);
//
//        /* Add payload */
//        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));
//
//        cose_sign_add_signer(&sign, &key);
//
//        /* Encode COSE sign object */
//        COSE_ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
//        CU_ASSERT_EQUAL(cur, 0);
//        if (cur) {
//            printf("Mem: Cur: %d, max: %d, total: %d, limit: %d, alloc_lim: %d\n", cur, max, total, cap_limit, alloc_limit);
//        }
//
//        if (res < 0)
//        {
//            continue;
//        }
//        if (prev_len)
//        {
//            int cmp = memcmp(psign, prev_result, res);
//            if (cmp != 0)
//            {
//                printf("Result: ");
//                print_bytestr(psign, res);
//                printf("\n");
//                printf("Prev  : ");
//                print_bytestr(prev_result, res);
//                printf("\n");
//            }
//            CU_ASSERT_EQUAL(cmp, 0);
//        }
//        memcpy(prev_result, psign, res);
//        prev_len = res;
//    }
//    for (unsigned i = 0; i <= 20; i++) {
//        cur = 0;
//        max = 0;
//        total = 0;
//        cap_limit = i;
//        alloc_limit = 1000;
//
//        cose_sign_t verify;
//        cose_sign_init(&verify, 0);
//        /* Decode again */
//        int decode_success = cose_sign_decode(&verify, psign, prev_len, &ct);
//        /* Verify with signature slot 0 */
//        if (decode_success == COSE_OK)
//        {
//            int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
//            CU_ASSERT_EQUAL(verification, 0);
//            /* Modify payload */
//            CU_ASSERT_EQUAL(cur, 0);
//        }
//    }
//}
//
//void test_sign5(void)
//{
//    cose_key_t key;
//    genkey(&key, pkx1, pky1, sk1);
//    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
//    prev_len = 0;
//    uint8_t *psign = NULL;
//    /* Should take 48 allocations max */
//    for (unsigned i = 0; i <= 60; i++)
//    {
//        cur = 0;
//        max = 0;
//        total = 0;
//        alloc_limit = i;
//        char sign1_payload[] = "Input string";
//        memset(buf, 0, sizeof(buf));
//        cose_sign_t sign;
//        /* Initialize struct */
//        cose_sign_init(&sign, 0);
//
//        /* Add payload */
//        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));
//
//        cose_sign_add_signer(&sign, &key);
//
//        /* Encode COSE sign object */
//        COSE_ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
//        CU_ASSERT_EQUAL(cur, 0);
//        if (res < 0)
//        {
//            continue;
//        }
//        if (prev_len)
//        {
//            int cmp = memcmp(psign, prev_result, res);
//            if (cmp != 0)
//            {
//                printf("Result: ");
//                print_bytestr(psign, res);
//                printf("\n");
//                printf("Prev  : ");
//                print_bytestr(prev_result, res);
//                printf("\n");
//            }
//            CU_ASSERT_EQUAL(cmp, 0);
//        }
//        memcpy(prev_result, psign, res);
//        prev_len = res;
//    }
//    for (unsigned i = 0; i <= 20; i++) {
//        cur = 0;
//        max = 0;
//        total = 0;
//        cap_limit = 50;
//        alloc_limit = i;
//
//        cose_sign_t verify;
//        cose_sign_init(&verify, 0);
//        /* Decode again */
//        int decode_success = cose_sign_decode(&verify, psign, prev_len, &ct);
//        /* Verify with signature slot 0 */
//        if (decode_success == COSE_OK)
//        {
//            int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
//            CU_ASSERT_NOT_EQUAL(verification, COSE_ERR_CRYPTO);
//            /* Modify payload */
//            CU_ASSERT_EQUAL(cur, 0);
//        }
//    }
//}
//
//void test_sign6(void)
//{
//    cose_key_t key, key2;
//    genkey(&key, pkx1, pky1, sk1);
//    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
//    genkey(&key2, pkx2, pky2, sk2);
//    cose_key_set_kid(&key2, (uint8_t*)kid2, sizeof(kid2) - 1);
//    prev_len = 0;
//    uint8_t *psign = NULL;
//    /* Should take 48 allocations max */
//    for (unsigned i = 0; i <= 85; i++)
//    {
//        cur = 0;
//        max = 0;
//        total = 0;
//        alloc_limit = i;
//        char sign1_payload[] = "Input string";
//        memset(buf, 0, sizeof(buf));
//        cose_sign_t sign;
//        /* Initialize struct */
//        cose_sign_init(&sign, 0);
//
//        /* Add payload */
//        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));
//
//        cose_sign_add_signer(&sign, &key);
//        cose_sign_add_signer(&sign, &key2);
//
//        /* Encode COSE sign object */
//        COSE_ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
//        CU_ASSERT_EQUAL(cur, 0);
//        if (res < 0)
//        {
//            continue;
//        }
//        if (prev_len)
//        {
//            int cmp = memcmp(psign, prev_result, res);
//            if (cmp != 0)
//            {
//                printf("Result: ");
//                print_bytestr(psign, res);
//                printf("\n");
//                printf("Prev  : ");
//                print_bytestr(prev_result, res);
//                printf("\n");
//            }
//            CU_ASSERT_EQUAL(cmp, 0);
//        }
//        memcpy(prev_result, psign, res);
//        prev_len = res;
//    }
//    for (unsigned i = 0; i <= 30; i++) {
//        cur = 0;
//        max = 0;
//        total = 0;
//        cap_limit = 50;
//        alloc_limit = i;
//
//        cose_sign_t verify;
//        cose_sign_init(&verify, 0);
//        /* Decode again */
//        int decode_success = cose_sign_decode(&verify, psign, prev_len, &ct);
//        /* Verify with signature slot 0 */
//        if (decode_success == COSE_OK)
//        {
//            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct), COSE_ERR_CRYPTO);
//            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 1, ver_buf, sizeof(ver_buf), &ct), COSE_OK);
//            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 1, ver_buf, sizeof(ver_buf), &ct), COSE_ERR_CRYPTO);
//            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 0, ver_buf, sizeof(ver_buf), &ct), COSE_OK);
//            /* Modify payload */
//            CU_ASSERT_EQUAL(cur, 0);
//        }
//    }
//}
//
//void test_sign7(void)
//{
//    cur = 0;
//    max = 0;
//    total = 0;
//    char sign1_payload[] = "Input string";
//    memset(buf, 0, sizeof(buf));
//    cose_sign_t sign;
//    cose_key_t key;
//    /* Initialize struct */
//    cose_sign_init(&sign, 0);
//
//    /* Add payload */
//    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));
//
//    /* First signer */
//    genkey(&key, pkx1, pky1, sk1);
//    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
//    for(int i = 0; i < COSE_SIGNATURES_MAX; i++) {
//        CU_ASSERT_EQUAL(cose_sign_add_signer(&sign, &key), i);
//    }
//    CU_ASSERT_EQUAL(cose_sign_add_signer(&sign, &key), COSE_ERR_NOMEM);
//    CU_ASSERT_EQUAL(cur, 0);
//}

/* Tagged 1 signer test */
void test_sign9(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signature_t signature, vsignature;
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

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    //cose_hdr_t *hdr = cose_sign_get_protected(&verify, COSE_HDR_CONTENT_TYPE);
    //CU_ASSERT_NOT_EQUAL(hdr, NULL);
    /* Verify with signature slot 0 */
    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
    int verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf));
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
}

/* External payload signer test */
void test_sign10(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signature_t signature, vsignature;
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

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);
    CU_ASSERT(verify.flags & COSE_FLAGS_EXTDATA);
    CU_ASSERT_EQUAL(verify.payload_len, 0);
    CU_ASSERT_EQUAL(verify.payload, NULL);
    cose_sign_set_payload(&verify, sign1_payload, strlen(sign1_payload));

    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));

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

/* External payload signer test */
void test_sign11(void)
{
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signature_t signature, vsignature;
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

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size);

    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));

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

void test_sign12(void)
{
    uint8_t *psign = NULL;
    char payload[] = "Input string";
    cose_sign_t sign, verify;
    cose_signature_t signature1, signature2, vsignature;
    cose_key_t key, key2;
    cose_hdr_t hdr42, hdr41, hdr45, hdr47;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_sign_init(&verify, 0);
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

    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, psign, len), 0);

    cose_sign_iter_t iter;
    cose_sign_iter_init(&verify, &iter);
    CU_ASSERT(cose_sign_iter(&iter, &vsignature));

    cose_hdr_t hdr;
    CU_ASSERT(cose_signature_get_protected(&vsignature, &hdr, 45));
    CU_ASSERT_EQUAL(hdr.v.value, -2);

    CU_ASSERT(cose_signature_get_unprotected(&vsignature, &hdr, 47));
    CU_ASSERT_EQUAL(hdr.v.value, -3);

    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);

    CU_ASSERT(cose_sign_iter(&iter, &vsignature));
    CU_ASSERT_FATAL(cose_signature_get_protected(&vsignature, &hdr, 42));
    CU_ASSERT_EQUAL(hdr.v.value, 3);

    CU_ASSERT_FATAL(cose_signature_get_unprotected(&vsignature, &hdr, 41));
    CU_ASSERT_EQUAL(hdr.v.value, 7);
    /* Test correct signature with correct key */
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &vsignature, &key, ver_buf, sizeof(ver_buf)), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &vsignature, &key2, ver_buf, sizeof(ver_buf)), 0);

    CU_ASSERT_FALSE(cose_sign_iter(&iter, &vsignature));
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
//    {
//        .f = test_sign4,
//        .n = "Sign memory limit capacity",
//    },
//    {
//        .f = test_sign5,
//        .n = "Sign memory limit allocations",
//    },
//    {
//        .f = test_sign6,
//        .n = "Sign memory limit allocation with 2 signers",
//    },
//    {
//        .f = test_sign7,
//        .n = "Signer memory exhaustion",
//    },
//    {
//        .f = test_sign8,
//        .n = "Signerature index out of bounds",
//    },
    {
        .f = test_sign9,
        .n = "Content type header test",
    },
    {
        .f = test_sign10,
        .n = "External payload header test",
    },
    {
        .f = test_sign11,
        .n = "Sign1 Sig headers test",
    },
    {
        .f = test_sign12,
        .n = "Sign Sig headers test",
    },
    {
        .f = NULL,
        .n = NULL,
    }
};
