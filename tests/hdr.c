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
#include "cose/hdr.h"
#include "cose/test.h"
#include <cn-cbor/cn-cbor.h>
#include <CUnit/CUnit.h>

/* CN_CBOR calloc functions */
static void *cose_calloc(size_t count, size_t size, void *context)
{
    (void)context;
    return calloc(count, size);
}

static void cose_free(void *ptr, void *context)
{
    (void)context;
    free(ptr);
}

static cn_cbor_context ct =
{
    .calloc_func = cose_calloc,
    .free_func = cose_free,
    .context = NULL
};

void test_hdr1(void)
{
    int val = 3278;
    int key = 5734;
    cose_hdr_t header;
    cn_cbor_errback errp;
    cn_cbor *cn_map = cn_cbor_map_create(&ct, &errp);
    cn_cbor *cn_value = cn_cbor_int_create(val, &ct, &errp);
    cn_cbor_mapput_int(cn_map, key, cn_value, &ct, &errp);
    CU_ASSERT(cose_hdr_from_cbor_map(&header, cn_map->first_child, &ct, &errp));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_INT);
    CU_ASSERT_EQUAL(header.v.value, val);
}

void test_hdr2(void)
{
    char str[] = "test string";
    int key = 5734;
    cose_hdr_t header;
    cn_cbor_errback errp;
    cn_cbor *cn_map = cn_cbor_map_create(&ct, &errp);
    cn_cbor *cn_value = cn_cbor_string_create(str, &ct, &errp);
    cn_cbor_mapput_int(cn_map, key, cn_value, &ct, &errp);
    CU_ASSERT(cose_hdr_from_cbor_map(&header, cn_map->first_child, &ct, &errp));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_TSTR);
    CU_ASSERT_EQUAL(memcmp(str,header.v.str, sizeof(str)), 0);
}

void test_hdr3(void)
{
    uint8_t str[] = "test string";
    int key = -4;
    cose_hdr_t header;
    cn_cbor_errback errp;
    cn_cbor *cn_map = cn_cbor_map_create(&ct, &errp);
    cn_cbor *cn_value = cn_cbor_data_create(str, sizeof(str), &ct, &errp);
    cn_cbor_mapput_int(cn_map, key, cn_value, &ct, &errp);
    CU_ASSERT(cose_hdr_from_cbor_map(&header, cn_map->first_child, &ct, &errp));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_BSTR);
    CU_ASSERT_EQUAL(memcmp(str,header.v.data, sizeof(str)), 0);
}

void test_hdr4(void)
{
    int key = -413;
    cose_hdr_t header;
    cn_cbor_errback errp;
    cn_cbor *cn_map = cn_cbor_map_create(&ct, &errp);
    cn_cbor *cn_value = cn_cbor_array_create(&ct, &errp);
    cn_cbor_mapput_int(cn_map, key, cn_value, &ct, &errp);
    CU_ASSERT(cose_hdr_from_cbor_map(&header, cn_map->first_child, &ct, &errp));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_CBOR);
    CU_ASSERT_EQUAL(header.v.cbor->type, CN_CBOR_ARRAY);
}

void test_hdr5(void)
{
    cose_hdr_t header = {
        .key = -34,
        .type = COSE_HDR_TYPE_INT,
        .v = { .value = 32 },
        .len = 0
    };
    cn_cbor *cn_map = cn_cbor_map_create(&ct, NULL);
    CU_ASSERT(cose_hdr_to_cbor_map(&header, cn_map, &ct, NULL));
    cn_cbor *key = cn_map->first_child;
    cn_cbor *value = key->next;
    CU_ASSERT_EQUAL(key->type, CN_CBOR_INT);
    CU_ASSERT_EQUAL(value->type, CN_CBOR_UINT);
    CU_ASSERT_EQUAL(value->v.uint, header.v.value);
}

void test_hdr6(void)
{
    char input[] = "Text input";
    cose_hdr_t header = {
        .key = 432,
        .type = COSE_HDR_TYPE_TSTR,
        .v = { .str = input },
        .len = 0
    };
    cn_cbor *cn_map = cn_cbor_map_create(&ct, NULL);
    CU_ASSERT(cose_hdr_to_cbor_map(&header, cn_map, &ct, NULL));
    cn_cbor *key = cn_map->first_child;
    cn_cbor *value = key->next;
    CU_ASSERT_EQUAL(key->type, CN_CBOR_UINT);
    CU_ASSERT_EQUAL(value->type, CN_CBOR_TEXT);
    CU_ASSERT_EQUAL(memcmp(value->v.str, header.v.str, sizeof(input)), 0);
}

void test_hdr7(void)
{
    uint8_t input[] = "Text input";
    cose_hdr_t header = {
        .key = 432,
        .type = COSE_HDR_TYPE_BSTR,
        .v = { .data = input },
        .len = 0
    };
    cn_cbor *cn_map = cn_cbor_map_create(&ct, NULL);
    CU_ASSERT(cose_hdr_to_cbor_map(&header, cn_map, &ct, NULL));
    cn_cbor *key = cn_map->first_child;
    cn_cbor *value = key->next;
    CU_ASSERT_EQUAL(key->type, CN_CBOR_UINT);
    CU_ASSERT_EQUAL(value->type, CN_CBOR_BYTES);
    CU_ASSERT_EQUAL(memcmp(value->v.bytes, header.v.data, sizeof(input)), 0);
}

void test_hdr8(void)
{
    cn_cbor *input = cn_cbor_map_create(&ct, NULL);
    cose_hdr_t header = {
        .key = 432,
        .type = COSE_HDR_TYPE_CBOR,
        .v = { .cbor = input },
        .len = 0
    };
    cn_cbor *cn_map = cn_cbor_map_create(&ct, NULL);
    CU_ASSERT(cose_hdr_to_cbor_map(&header, cn_map, &ct, NULL));
    cn_cbor *key = cn_map->first_child;
    cn_cbor *value = key->next;
    CU_ASSERT_EQUAL(key->type, CN_CBOR_UINT);
    CU_ASSERT_EQUAL(value->type, CN_CBOR_MAP);
}

void test_hdr9(void)
{
    char str[] = "test string";
    cose_hdr_t header;
    cn_cbor_errback errp;
    cn_cbor *cn_map = cn_cbor_map_create(&ct, &errp);
    cn_cbor *cn_value = cn_cbor_string_create(str, &ct, &errp);
    cn_cbor_mapput_string(cn_map, str, cn_value, &ct, &errp);
    CU_ASSERT_FALSE(cose_hdr_from_cbor_map(&header, cn_map->first_child, &ct, &errp));
}


const test_t tests_hdr[] = {
    {
        .f = test_hdr1,
        .n = "Simple cbor to hdr conversion",
    },
    {
        .f = test_hdr2,
        .n = "Text cbor to hdr conversion",
    },
    {
        .f = test_hdr3,
        .n = "Bytes cbor to hdr conversion",
    },
    {
        .f = test_hdr4,
        .n = "CBOR content cbor to hdr conversion",
    },
    {
        .f = test_hdr5,
        .n = "header to CBOR conversion",
    },
    {
        .f = test_hdr6,
        .n = "header with string to CBOR conversion",
    },
    {
        .f = test_hdr7,
        .n = "header with bytes to CBOR conversion",
    },
    {
        .f = test_hdr8,
        .n = "header with CBOR to CBOR conversion",
    },
    {
        .f = test_hdr9,
        .n = "Invalid header conversion to CBOR",
    },
    {
        .f = NULL,
        .n = NULL,
    }
};
