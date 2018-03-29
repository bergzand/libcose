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
static unsigned char pk[crypto_sign_PUBLICKEYBYTES];
static unsigned char sk[crypto_sign_SECRETKEYBYTES];
static unsigned char pk2[crypto_sign_PUBLICKEYBYTES];
static unsigned char sk2[crypto_sign_SECRETKEYBYTES];

/* Memory usage tracking */
static int max = 0;
static int cur = 0;
static int total = 0;
static int cap_limit = 1000;
static int alloc_limit = 1000;

#define MLEN (sizeof(payload))
#define SMLEN (sizeof(payload)+ crypto_sign_BYTES)
#define NUM_TESTS (sizeof(tests)/sizeof(struct test))
static uint8_t buf[2048];
static uint8_t prev_result[2048];
static size_t prev_len = 0;

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
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signer_t signer;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signer);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &ct);

    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, buf + 64, encode_size, &ct);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &signer, 0, &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &signer, 0, &ct);
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
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signer_t signer;
    /* Initialize struct */
    cose_sign_init(&sign, COSE_FLAGS_UNTAGGED);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signer);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &ct);

    CU_ASSERT_NOT_EQUAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, buf + 64, encode_size, &ct);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &signer, 0, &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &signer, 0, &ct);
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
    char payload[] = "Input string";
    cose_sign_t sign, verify;
    cose_signer_t signer, signer2;
    cn_cbor_errback errp;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_sign_init(&verify, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, payload, strlen(payload));

    /* First signer */
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

    /* Second signer */
    cose_crypto_keypair_ed25519(pk2, sk2);
    cose_signer_init(&signer2);
    cose_signer_set_keys(&signer2, COSE_EC_CURVE_ED25519, pk2, NULL, sk2);
    cose_signer_set_kid(&signer2, (uint8_t*)kid2, sizeof(kid2) - 1);
    cose_sign_add_signer(&sign, &signer);
    cose_sign_add_signer(&sign, &signer2);

    CU_ASSERT(cose_signer_serialize_protected(&signer, NULL, 0, &ct, &errp) > 0);

    size_t len = cose_sign_encode(&sign, buf, sizeof(buf), &ct);

    print_bytestr(buf+128, len);
    printf("\n");

    CU_ASSERT_EQUAL_FATAL(cose_sign_decode(&verify, buf + 128, len, &ct), 0);
    /* Test correct signature with correct signer */
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &signer, 0, &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer, 1, &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer2, 0, &ct), 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&verify, &signer2, 1, &ct), 0);
    /* Modify payload */
    ((int*)verify.payload)[0]++;
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer, 0, &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer, 1, &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer2, 0, &ct), 0);
    CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer2, 1, &ct), 0);

    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign4(void)
{
    cose_signer_t signer;
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);
    printf("\n");
    for (int i = 0; i <= 20; i++)
    {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = i;
        char sign1_payload[] = "Input string";
        memset(buf, 0, sizeof(buf));
        cose_sign_t sign;
        cose_signer_t signer;
        /* Initialize struct */
        cose_sign_init(&sign, 0);

        /* Add payload */
        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

        /* First signer */
        cose_signer_init(&signer);
        cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
        cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

        cose_sign_add_signer(&sign, &signer);

        /* Encode COSE sign object */
        ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &ct);
        CU_ASSERT_EQUAL(cur, 0);
        if (res < 0)
        {
            continue;
        }
        if (prev_len)
        {
            int cmp = memcmp(buf+64, prev_result, res);
            if (cmp != 0)
            {
                printf("Result: ");
                print_bytestr(buf+64, res);
                printf("\n");
                printf("Prev  : ");
                print_bytestr(prev_result, res);
                printf("\n");
            }
            CU_ASSERT_EQUAL(cmp, 0);
        }
        memcpy(prev_result, buf+64, res);
        prev_len = res;
    }
    for (int i = 0; i <= 20; i++) {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = i;
        alloc_limit = 1000;

        cose_sign_t verify;
        cose_sign_init(&verify, 0);
        /* Decode again */
        int decode_success = cose_sign_decode(&verify, buf + 64, prev_len, &ct);
        /* Verify with signature slot 0 */
        if (decode_success == COSE_OK)
        {
            int verification = cose_sign_verify(&verify, &signer, 0, &ct);
            CU_ASSERT_EQUAL(verification, 0);
            /* Modify payload */
            CU_ASSERT_EQUAL(cur, 0);
        }
    }
}

void test_sign5(void)
{
    cose_signer_t signer;
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);
    prev_len = 0;
    printf("\n");
    /* Should take 48 allocations max */
    for (int i = 0; i <= 60; i++)
    {
        cur = 0;
        max = 0;
        total = 0;
        alloc_limit = i;
        char sign1_payload[] = "Input string";
        memset(buf, 0, sizeof(buf));
        cose_sign_t sign;
        cose_signer_t signer;
        /* Initialize struct */
        cose_sign_init(&sign, 0);

        /* Add payload */
        cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

        /* First signer */
        cose_signer_init(&signer);
        cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
        cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

        cose_sign_add_signer(&sign, &signer);

        /* Encode COSE sign object */
        ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &ct);
        if (res > 0) {
        }
        CU_ASSERT_EQUAL(cur, 0);
        if (res < 0)
        {
            continue;
        }
        if (prev_len)
        {
            int cmp = memcmp(buf+64, prev_result, res);
            if (cmp != 0)
            {
                printf("Result: ");
                print_bytestr(buf+64, res);
                printf("\n");
                printf("Prev  : ");
                print_bytestr(prev_result, res);
                printf("\n");
            }
            CU_ASSERT_EQUAL(cmp, 0);
        }
        memcpy(prev_result, buf+64, res);
        prev_len = res;
    }
    for (int i = 0; i <= 20; i++) {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = 50;
        alloc_limit = i;

        cose_sign_t verify;
        cose_sign_init(&verify, 0);
        /* Decode again */
        int decode_success = cose_sign_decode(&verify, buf + 64, prev_len, &ct);
        /* Verify with signature slot 0 */
        if (decode_success == COSE_OK)
        {
            int verification = cose_sign_verify(&verify, &signer, 0, &ct);
            CU_ASSERT_NOT_EQUAL(verification, COSE_ERR_CRYPTO);
            /* Modify payload */
            CU_ASSERT_EQUAL(cur, 0);
        }
    }
}

void test_sign6(void)
{
    cose_signer_t signer, signer2;
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);
    cose_signer_init(&signer2);
    cose_signer_set_keys(&signer2, COSE_EC_CURVE_ED25519, pk2, NULL, sk2);
    cose_signer_set_kid(&signer2, (uint8_t*)kid2, sizeof(kid2) - 1);
    prev_len = 0;
    printf("\n");
    /* Should take 48 allocations max */
    for (int i = 0; i <= 85; i++)
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

        /* First signer */
        cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

        cose_sign_add_signer(&sign, &signer);
        cose_sign_add_signer(&sign, &signer2);

        /* Encode COSE sign object */
        ssize_t res = cose_sign_encode(&sign, buf, sizeof(buf), &ct);
        if (res > 0) {
        }
        CU_ASSERT_EQUAL(cur, 0);
        if (res < 0)
        {
            continue;
        }
        if (prev_len)
        {
            int cmp = memcmp(buf+64, prev_result, res);
            if (cmp != 0)
            {
                printf("Result: ");
                print_bytestr(buf+64, res);
                printf("\n");
                printf("Prev  : ");
                print_bytestr(prev_result, res);
                printf("\n");
            }
            CU_ASSERT_EQUAL(cmp, 0);
        }
        memcpy(prev_result, buf+64, res);
        prev_len = res;
    }
    for (int i = 0; i <= 30; i++) {
        cur = 0;
        max = 0;
        total = 0;
        cap_limit = 50;
        alloc_limit = i;

        cose_sign_t verify;
        cose_sign_init(&verify, 0);
        /* Decode again */
        int decode_success = cose_sign_decode(&verify, buf + 128, prev_len, &ct);
        /* Verify with signature slot 0 */
        if (decode_success == COSE_OK)
        {
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer, 0, &ct), COSE_ERR_CRYPTO);
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer, 1, &ct), COSE_OK);
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer2, 1, &ct), COSE_ERR_CRYPTO);
            CU_ASSERT_NOT_EQUAL(cose_sign_verify(&verify, &signer2, 0, &ct), COSE_OK);
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
    cose_signer_t signer;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);
    for(int i = 0; i < COSE_SIGNATURES_MAX; i++) {
        CU_ASSERT_EQUAL(cose_sign_add_signer(&sign, &signer), COSE_OK);
    }
    CU_ASSERT_EQUAL(cose_sign_add_signer(&sign, &signer), COSE_ERR_NOMEM);
    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign8(void)
{
    cur = 0;
    max = 0;
    total = 0;
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign;
    cose_signer_t signer;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    CU_ASSERT_EQUAL(cose_sign_verify(&sign, &signer, COSE_SIGNATURES_MAX, &ct), COSE_ERR_NOMEM);

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

    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signer_t signer;
    /* Initialize struct */
    cose_sign_init(&sign, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signer);
    /* Octet stream content type */
    cose_sign_set_ct(&sign, 42);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &ct);
    printf("Encode size: %d\n", (signed)encode_size);
    printf("\n");
    print_bytestr(buf+64, encode_size);
    printf("\n");

    CU_ASSERT_NOT_EQUAL_FATAL(encode_size, 0);

    cose_sign_init(&verify, 0);
    /* Decode again */
    int decode_success = cose_sign_decode(&verify, buf + 64, encode_size, &ct);
    cose_hdr_t *hdr = cose_sign_get_protected(&verify, COSE_HDR_CONTENT_TYPE);
    CU_ASSERT_NOT_EQUAL(hdr, NULL);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL_FATAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &signer, 0, &ct);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &signer, 0, &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
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
        .f = NULL,
        .n = NULL,
    }
};
