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
#include <string.h>
#include "cose/hdr.h"
#include "cose/test.h"
#include "cose_defines.h"
#include <nanocbor/nanocbor.h>
#include <cbor.h>
#include <CUnit/CUnit.h>

#define HDRS_SIZE   4

#define BUF_SIZE    128
static uint8_t buf[BUF_SIZE];

void test_hdr1(void)
{
    const int val = 3278;
    const int key = 5734;
    nanocbor_encoder_t enc;
    cose_hdr_t header;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    nanocbor_fmt_int(&enc, key);
    nanocbor_fmt_int(&enc, val);
    size_t len = nanocbor_encoded_len(&enc);

    CU_ASSERT(cose_hdr_decode_from_cbor(buf, len, &header, key));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_INT);
    CU_ASSERT_EQUAL(header.v.value, val);
}

void test_hdr2(void)
{
    const char str[] = "test string";
    const int key = 5734;
    nanocbor_encoder_t enc;
    cose_hdr_t header;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    nanocbor_fmt_int(&enc, key);
    nanocbor_put_tstr(&enc, str);
    size_t len = nanocbor_encoded_len(&enc);

    CU_ASSERT(cose_hdr_decode_from_cbor(buf, len, &header, key));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_TSTR);
    CU_ASSERT_EQUAL(memcmp(str,header.v.str, sizeof(str)), 0);
}

void test_hdr3(void)
{
    const uint8_t str[] = "test string";
    const int key = -4;
    nanocbor_encoder_t enc;
    cose_hdr_t header;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    nanocbor_fmt_int(&enc, key);
    nanocbor_put_bstr(&enc, str, sizeof(str));
    size_t len = nanocbor_encoded_len(&enc);

    CU_ASSERT(cose_hdr_decode_from_cbor(buf, len, &header, key));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_BSTR);
    CU_ASSERT_EQUAL(memcmp(str,header.v.data, sizeof(str)), 0);
}

void test_hdr5(void)
{
    cose_hdr_t header = {
        .key = -34,
        .type = COSE_HDR_TYPE_INT,
        .v = { .value = 32 },
        .len = 0
    };
    nanocbor_encoder_t enc;
    nanocbor_value_t decode, imap;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    CU_ASSERT_EQUAL(cose_hdr_encode_to_map(&header, &enc), 0);
    size_t len = nanocbor_encoded_len(&enc);

    nanocbor_decoder_init(&decode, buf, len);
    nanocbor_enter_map(&decode, &imap);

    int32_t val;
    CU_ASSERT(nanocbor_get_int32(&imap, &val) > NANOCBOR_OK);
    CU_ASSERT_EQUAL(val, header.key);
    CU_ASSERT(nanocbor_get_int32(&imap, &val) > NANOCBOR_OK);
    CU_ASSERT_EQUAL(val, header.v.value);
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
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    CU_ASSERT_EQUAL(cose_hdr_encode_to_map(&header, &enc), 0);
    size_t len = nanocbor_encoded_len(&enc);

    nanocbor_value_t decode, imap;
    nanocbor_decoder_init(&decode, buf, len);
    nanocbor_enter_map(&decode, &imap);

    int32_t val = 0;
    const uint8_t *str = NULL;
    size_t str_len = 0;
    CU_ASSERT(nanocbor_get_int32(&imap, &val) > NANOCBOR_OK);
    CU_ASSERT_EQUAL(val, header.key);
    CU_ASSERT_EQUAL(nanocbor_get_tstr(&imap, &str, &str_len), NANOCBOR_OK);
    CU_ASSERT_EQUAL(memcmp(str, header.v.str, str_len), 0);
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
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    CU_ASSERT_EQUAL(cose_hdr_encode_to_map(&header, &enc), 0);
    size_t len = nanocbor_encoded_len(&enc);

    nanocbor_value_t decode, imap;
    nanocbor_decoder_init(&decode, buf, len);
    nanocbor_enter_map(&decode, &imap);

    int val;
    const uint8_t *str = NULL;
    size_t str_len = 0;
    CU_ASSERT(nanocbor_get_int32(&imap, &val) > NANOCBOR_OK);
    CU_ASSERT_EQUAL(val, header.key);
    CU_ASSERT_EQUAL(nanocbor_get_bstr(&imap, &str, &str_len), NANOCBOR_OK);
    CU_ASSERT_EQUAL(memcmp(str, header.v.str, str_len), 0);
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
        .f = NULL,
        .n = NULL,
    }
};
