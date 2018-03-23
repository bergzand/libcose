/*
 * Copyright (C) 2018 Freie Universität Berlin
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

#define MLEN (sizeof(payload))
#define SMLEN (sizeof(payload)+ crypto_sign_BYTES)
#define NUM_TESTS (sizeof(tests)/sizeof(struct test))
static uint8_t buf[2048];

static void print_bytestr(uint8_t *bytes, size_t len)
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

void test_sign1(void)
{
    cur = 0;
    max = 0;
    char sign1_payload[] = "Input string";
    memset(buf, 0, sizeof(buf));
    cose_sign_t sign, verify;
    cose_signer_t signer;
    cn_cbor_errback errp;
    /* Initialize struct */
    cose_sign_init(&sign, COSE_FLAGS_UNTAGGED);
    cose_sign_init(&verify, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, sign1_payload, strlen(sign1_payload));

    /* First signer */
    cose_crypto_keypair_ed25519(pk, sk);
    cose_signer_init(&signer);
    cose_signer_set_keys(&signer, COSE_EC_CURVE_ED25519, pk, NULL, sk);
    cose_signer_set_kid(&signer, (uint8_t*)kid, sizeof(kid) - 1);

    cose_sign_add_signer(&sign, &signer, &ct, &errp);

    /* Encode COSE sign object */
    size_t encode_size = cose_sign_encode(&sign, buf, sizeof(buf), &ct, &errp);
    printf("Encoded size for sign1: %lu\n", encode_size);
    print_bytestr(buf+64, encode_size);
    printf("\n");
    printf("Signature: ");
    print_bytestr(buf, 64);
    printf("\n");


    CU_ASSERT_NOT_EQUAL(encode_size, 0);

    /* Decode again */
    int decode_success = cose_sign_decode(&verify, buf + 64, encode_size, &ct, &errp);
    /* Verify with signature slot 0 */
    CU_ASSERT_EQUAL(decode_success, 0);
    int verification = cose_sign_verify(&verify, &signer, 0, &ct);
    printf("Verification: %d\n", verification);
    CU_ASSERT_EQUAL(verification, 0);
    /* Modify payload */
    ((int*)(verify.payload))[0]++;
    verification = cose_sign_verify(&verify, &signer, 0, &ct);
    /* Should fail due to modified payload */
    CU_ASSERT_NOT_EQUAL(verification, 0);
    printf("Current usage %d, Max usage: %d\n", cur, max);
    CU_ASSERT_EQUAL(cur, 0);
}

void test_sign2(void)
{
    cur = 0;
    max = 0;
    char payload[] = "Input string";
    cose_sign_t sign, verify;
    cose_signer_t signer, signer2;
    cn_cbor_errback errp;
    /* Initialize struct */
    cose_sign_init(&sign, 0);
    cose_sign_init(&verify, 0);

    /* Add payload */
    cose_sign_set_payload(&sign, payload, sizeof(payload));

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
    cose_sign_add_signer(&sign, &signer, &ct, &errp);
    cose_sign_add_signer(&sign, &signer2, &ct, &errp);

    CU_ASSERT(cose_signer_serialize_protected(&signer, NULL, 0, &ct, &errp) > 0);

    size_t len = cose_sign_encode(&sign, buf, sizeof(buf), &ct, &errp);


    CU_ASSERT_EQUAL(cose_sign_decode(&verify, buf + 128, len, &ct, &errp), 0);
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

    printf("Current usage %d, Max usage: %d\n", cur, max);
    CU_ASSERT_EQUAL(cur, 0);
}

const test_t tests_sign[] = {
    {
        .f = test_sign1,
        .n = "Sign with 1 sig",
    },
    {
        .f = test_sign2,
        .n = "Sign with two sigs",
    },
    {
        .f = NULL,
        .n = NULL,
    }
};
