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
#include "cose.h"
#include "cose_defines.h"

#include "cose/test.h"

#include "CUnit/CUnit.h"
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"

static char kid[] = "koen@example.org";
static char kid2[] = "koen@example.org";

#ifdef HAVE_ALGO_EDDSA
#define TEST_CRYPTO_SIGN_PUBLICKEYBYTES COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES
#define TEST_CRYPTO_SIGN_SECRETKEYBYTES COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES
#elif defined(HAVE_ALGO_ECDSA)
#define TEST_CRYPTO_SIGN_PUBLICKEYBYTES COSE_CRYPTO_SIGN_P521_PUBLICKEYBYTES
#define TEST_CRYPTO_SIGN_SECRETKEYBYTES COSE_CRYPTO_SIGN_P521_SECRETKEYBYTES
#endif


static unsigned char pkx[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char pky[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char sk[TEST_CRYPTO_SIGN_SECRETKEYBYTES];
static unsigned char pkx2[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char pky2[TEST_CRYPTO_SIGN_PUBLICKEYBYTES];
static unsigned char sk2[TEST_CRYPTO_SIGN_SECRETKEYBYTES];

/* Memory usage tracking */
static int max = 0;
static int cur = 0;
static int total = 0;
static int cap_limit = 1000;
static int alloc_limit = 1000;

#define NUM_TESTS (sizeof(tests)/sizeof(struct test))
static uint8_t buf[2048];
static uint8_t ver_buf[2048];
static uint8_t prev_result[2048];
static size_t prev_len = 0;

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

/* CN_CBOR calloc functions */
static void *cose_calloc(size_t count, size_t size, void *context)
{
    (void)context;
    if (cur >= cap_limit)
    {
        return NULL;
    }
    if (total >= alloc_limit)
    {
        return NULL;
    }
    total++;
    cur++;
    if(cur > max)
    {
        max = cur;
    }
    return calloc(count, size);
}

static void cose_free(void *ptr, void *context)
{
    (void)context;
    cur--;
    free(ptr);
}

static cn_cbor_context ct =
{
    .calloc_func = cose_calloc,
    .free_func = cose_free,
    .context = NULL
};

/* Tagged 1 signer test */
void test_sign1(void)
{
    cur = 0;
    max = 0;
    total = 0;
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &key);

    /* Encode COSE sign object */
    ssize_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);

    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);
    printf("Encode size: %ld\n", encode_size);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size, &ct);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
    printf("Current usage %d, Max usage: %d\n", cur, max);
    CU_ASSERT_EQUAL(cur, 0);
}

/* Untagged 1 signer test */
void test_sign2(void)
{
    cur = 0;
    max = 0;
    total = 0;
    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, COSE_FLAGS_UNTAGGED);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    cose_sign_add_signer(&sign, &key);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);

    CU_ASSERT_NOT_EQUAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size, &ct);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
    printf("Current usage %d, Max usage: %d\n", cur, max);
    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign3(void)
{
    cur = 0;
    max = 0;
    total = 0;
    uint8_t *psign = NULL;
    char payload[] = "Input string";
    cose_sign_t sign, verify;
    cose_key_t key, key2;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_sign_init(&verify, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, payload, strlen(payload));

    /* First signer */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    /* Second signer */
    genkey(&key2, pkx2, pky2, sk2);
    cose_key_set_kid(&key2, (uint8_t*)kid2, sizeof(kid2) - 1);
    cose_sign_add_signer(&sign, &key);
    cose_sign_add_signer(&sign, &key2);

    size_t len = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);

    print_bytestr(psign, len);
    printf("\n");

    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, psign, len, &ct), 0);
    /* Test correct signature with correct signer */
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 1, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 0, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &key2, 1, ver_buf, sizeof(ver_buf), &ct), 0);
    /* Modify payload */
    ((int*)verify.payload)[0]++;
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 1, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 0, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 1, ver_buf, sizeof(ver_buf), &ct), 0);

    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign4(void)
{
    cose_key_t key;
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    uint8_t *psign = NULL;
    for (unsigned i = 0; i <= 20; i++)
    {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = i;
        char sign1_payload[] = "Input string";
        memset(buf, 0, sizeof(buf));
        cose_sign_t sign;
        /* Initialize struct */
        cose_sign_init(&sign, 0);

        /* Add payload */
        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

        cose_sign_add_signer(&sign, &key);

        /* Encode COSE sign object */
        ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
        CU_ASSERT_EQUAL(cur, 0);
        if (cur) {
            printf("Mem: Cur: %d, max: %d, total: %d, limit: %d, alloc_lim: %d\n", cur, max, total, cap_limit, alloc_limit);
        }

        if (res < 0)
        {
            continue;
        }
        if (prev_len)
        {
            int cmp = memcmp(psign, prev_result, res);
            if (cmp != 0)
            {
                printf("Result: ");
                print_bytestr(psign, res);
                printf("\n");
                printf("Prev  : ");
                print_bytestr(prev_result, res);
                printf("\n");
            }
            CU_ASSERT_EQUAL(cmp, 0);
        }
        memcpy(prev_result, psign, res);
        prev_len = res;
    }
    for (unsigned i = 0; i <= 20; i++) {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = i;
        alloc_limit = 1000;

        cose_sign_t verify;
        cose_sign_init(&verify, 0);
        /* Decode again */
        int decode_success = cose_sign_decode(&verify, psign, prev_len, &ct);
        /* Verify with signature slot 0 */
        if (decode_success == COSE_OK)
        {
            int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
            CU_ASSERT_EQUAL(verification, 0);
            /* Modify payload */
            CU_ASSERT_EQUAL(cur, 0);
        }
    }
}

void test_sign5(void)
{
    cose_key_t key;
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    prev_len = 0;
    uint8_t *psign = NULL;
    /* Should take 48 allocations max */
    for (unsigned i = 0; i <= 60; i++)
    {
        cur = 0;
        max = 0;
        total = 0;
        alloc_limit = i;
        char sign1_payload[] = "Input string";
        memset(buf, 0, sizeof(buf));
        cose_sign_t sign;
        cose_key_t key;
        /* Initialize struct */
        cose_sign_init(&sign, 0);

        /* Add payload */
        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));


        cose_sign_add_signer(&sign, &key);

        /* Encode COSE sign object */
        ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
        if (res > 0) {
        }
        CU_ASSERT_EQUAL(cur, 0);
        if (res < 0)
        {
            continue;
        }
        if (prev_len)
        {
            int cmp = memcmp(psign, prev_result, res);
            if (cmp != 0)
            {
                printf("Result: ");
                print_bytestr(psign, res);
                printf("\n");
                printf("Prev  : ");
                print_bytestr(prev_result, res);
                printf("\n");
            }
            CU_ASSERT_EQUAL(cmp, 0);
        }
        memcpy(prev_result, psign, res);
        prev_len = res;
    }
    for (unsigned i = 0; i <= 20; i++) {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = 50;
        alloc_limit = i;

        cose_sign_t verify;
        cose_sign_init(&verify, 0);
        /* Decode again */
        int decode_success = cose_sign_decode(&verify, psign, prev_len, &ct);
        /* Verify with signature slot 0 */
        if (decode_success == COSE_OK)
        {
            int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
            CU_ASSERT_NOT_EQUAL(verification, COSE_ERR_CRYPTO);
            /* Modify payload */
            CU_ASSERT_EQUAL(cur, 0);
        }
    }
}

void test_sign6(void)
{
    cose_key_t key, key2;
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    genkey(&key2, pkx2, pky2, sk2);
    cose_key_set_kid(&key2, (uint8_t*)kid2, sizeof(kid2) - 1);
    prev_len = 0;
    uint8_t *psign = NULL;
    /* Should take 48 allocations max */
    for (unsigned i = 0; i <= 85; i++)
    {
        cur = 0;
        max = 0;
        total = 0;
        alloc_limit = i;
        char sign1_payload[] = "Input string";
        memset(buf, 0, sizeof(buf));
        cose_sign_t sign;
        /* Initialize struct */
        cose_sign_init(&sign, 0);

        /* Add payload */
        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

        cose_sign_add_signer(&sign, &key);
        cose_sign_add_signer(&sign, &key2);

        /* Encode COSE sign object */
        ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
        CU_ASSERT_EQUAL(cur, 0);
        if (res < 0)
        {
            continue;
        }
        if (prev_len)
        {
            int cmp = memcmp(psign, prev_result, res);
            if (cmp != 0)
            {
                printf("Result: ");
                print_bytestr(psign, res);
                printf("\n");
                printf("Prev  : ");
                print_bytestr(prev_result, res);
                printf("\n");
            }
            CU_ASSERT_EQUAL(cmp, 0);
        }
        memcpy(prev_result, psign, res);
        prev_len = res;
    }
    for (unsigned i = 0; i <= 30; i++) {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = 50;
        alloc_limit = i;

        cose_sign_t verify;
        cose_sign_init(&verify, 0);
        /* Decode again */
        int decode_success = cose_sign_decode(&verify, psign, prev_len, &ct);
        /* Verify with signature slot 0 */
        if (decode_success == COSE_OK)
        {
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct), COSE_ERR_CRYPTO);
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 1, ver_buf, sizeof(ver_buf), &ct), COSE_OK);
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 1, ver_buf, sizeof(ver_buf), &ct), COSE_ERR_CRYPTO);
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 0, ver_buf, sizeof(ver_buf), &ct), COSE_OK);
            /* Modify payload */
            CU_ASSERT_EQUAL(cur, 0);
        }
    }
}

void test_sign7(void)
{
    cur = 0;
    max = 0;
    total = 0;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    for(int i = 0; i < COSE_SIGNATURES_MAX; i++) {
        CU_ASSERT_EQUAL(cose_sign_add_signer(&sign, &key), i);
    }
    CU_ASSERT_EQUAL(cose_sign_add_signer(&sign, &key), COSE_ERR_NOMEM);
    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign8(void)
{
    cur = 0;
    max = 0;
    total = 0;
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&sign, &key, COSE_SIGNATURES_MAX, ver_buf, sizeof(ver_buf), &ct), COSE_ERR_NOMEM);

    CU_ASSERT_EQUAL(cur, 0);
}

/* Tagged 1 signer test */
void test_sign9(void)
{
    cur = 0;
    max = 0;
    total = 0;
    cap_limit = 1000;
    alloc_limit = 1000;

    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &key);
    /* Octet stream content type */
    cose_sign_set_ct(&sign, 42);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);

    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size, &ct);
    cose_hdr_t *hdr = cose_sign_get_protected(&verify, COSE_HDR_CONTENT_TYPE);
    CU_ASSERT_NOT_EQUAL(hdr, NULL);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
    CU_ASSERT_EQUAL(cur, 0);
}

/* External payload signer test */
void test_sign10(void)
{
    cur = 0;
    max = 0;
    total = 0;
    cap_limit = 1000;
    alloc_limit = 1000;

    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, COSE_FLAGS_EXTDATA);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    cose_sign_add_signer(&sign, &key);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size, &ct);
    CU_ASSERT(verify.flags & COSE_FLAGS_EXTDATA);
    CU_ASSERT_EQUAL(verify.payload_len, 0);
    CU_ASSERT_EQUAL(verify.payload, NULL);
    cose_sign_set_payload(&verify, sign1_payload, strlen(sign1_payload));

    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
    CU_ASSERT_EQUAL(cur, 0);
}

/* External payload signer test */
void test_sign11(void)
{
    cur = 0;
    max = 0;
    total = 0;
    cap_limit = 1000;
    alloc_limit = 1000;

    uint8_t *psign = NULL;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_key_t key;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First key */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);
    int idx = cose_sign_add_signer(&sign, &key);
    /* Dummy headers */
    cose_sign_sig_add_hdr_value(&sign, idx, 42, COSE_HDR_FLAGS_PROTECTED, 3);
    cose_sign_sig_add_hdr_value(&sign, idx, 43, COSE_HDR_FLAGS_PROTECTED, -8);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, psign, encode_size, &ct);

    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);

    cose_hdr_t *hdr = cose_sign_sig_get_protected(&verify, 0, 42);
    CU_ASSERT_FATAL((bool)hdr);
    CU_ASSERT_EQUAL(hdr->v.value, 3);

    hdr = cose_sign_sig_get_protected(&verify, 0, 43);
    CU_ASSERT_FATAL((bool)hdr);
    CU_ASSERT_EQUAL(hdr->v.value, -8);

    int verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign12(void)
{
    cur = 0;
    max = 0;
    total = 0;
    uint8_t *psign = NULL;
    char payload[] = "Input string";
    cose_sign_t sign, verify;
    cose_key_t key, key2;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_sign_init(&verify, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, payload, strlen(payload));

    /* First key */
    genkey(&key, pkx, pky, sk);
    cose_key_set_kid(&key, (uint8_t*)kid, sizeof(kid) - 1);

    /* Second signer */
    genkey(&key2, pkx2, pky2, sk2);
    cose_key_set_kid(&key2, (uint8_t*)kid2, sizeof(kid2) - 1);

    int idx = cose_sign_add_signer(&sign, &key);
    cose_sign_sig_add_hdr_value(&sign, idx, 42, COSE_HDR_FLAGS_PROTECTED, 3);
    cose_sign_sig_add_hdr_value(&sign, idx, 41, COSE_HDR_FLAGS_UNPROTECTED, 7);

    idx = cose_sign_add_signer(&sign, &key2);
    cose_sign_sig_add_hdr_value(&sign, idx, 45, COSE_HDR_FLAGS_PROTECTED, -2);
    cose_sign_sig_add_hdr_value(&sign, idx, 47, COSE_HDR_FLAGS_UNPROTECTED, -3);

    size_t len = cose_sign_encode(&sign, buf, sizeof(buf), &psign, &ct);
    printf("\n");
    print_bytestr(psign, len);
    printf("\n");

    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, psign, len, &ct), 0);

    cose_hdr_t *hdr = cose_sign_sig_get_protected(&verify, 0, 42);
    CU_ASSERT_FATAL((bool)hdr);
    CU_ASSERT_EQUAL(hdr->v.value, 3);

    hdr = cose_sign_sig_get_unprotected(&verify, 0, 41);
    CU_ASSERT_FATAL((bool)hdr);
    CU_ASSERT_EQUAL(hdr->v.value, 7);

    hdr = cose_sign_sig_get_protected(&verify, 1, 45);
    CU_ASSERT_FATAL((bool)hdr);
    CU_ASSERT_EQUAL(hdr->v.value, -2);

    hdr = cose_sign_sig_get_unprotected(&verify, 1, 47);
    CU_ASSERT_FATAL((bool)hdr);
    CU_ASSERT_EQUAL(hdr->v.value, -3);

    /* Test correct signature with correct key */
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &key, 0, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key, 1, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &key2, 0, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &key2, 1, ver_buf, sizeof(ver_buf), &ct), 0);
    CU_ASSERT_EQUAL(cur, 0);
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
        .n = "Sign memory limit capacity",
    },
    {
        .f = test_sign5,
        .n = "Sign memory limit allocations",
    },
    {
        .f = test_sign6,
        .n = "Sign memory limit allocation with 2 signers",
    },
    {
        .f = test_sign7,
        .n = "Signer memory exhaustion",
    },
    {
        .f = test_sign8,
        .n = "Signerature index out of bounds",
    },
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
