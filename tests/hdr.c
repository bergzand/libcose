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
#include <cbor.h>
#include <nanocbor/nanocbor.h>
#include <CUnit/CUnit.h>

#define HDRS_SIZE   4

#define BUF_SIZE    128
static uint8_t buf[BUF_SIZE];

static int cose_cbor_get_string(const CborValue *it, const uint8_t **cbuf, size_t *len)
{
    if (!(cbor_value_is_text_string(it) || cbor_value_is_byte_string(it) || cbor_value_is_length_known(it))) {
         return COSE_ERR_INVALID_CBOR;
    }
    CborValue next = *it;
    cbor_value_get_string_length(it, len);
    cbor_value_advance(&next);
    *cbuf = next.ptr - *len;
    return COSE_OK;
}

void test_hdr1(void)
{
    int val = 3278;
    int key = 5734;
    CborEncoder enc, map;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_int(&map, key);
    cbor_encode_int(&map, val);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

    CU_ASSERT(cose_hdr_decode_from_cbor(buf, len, &header, key));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_INT);
    CU_ASSERT_EQUAL(header.v.value, val);
}

void test_hdr2(void)
{
    char str[] = "test string";
    int key = 5734;
    CborEncoder enc, map;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_int(&map, key);
    cbor_encode_text_stringz(&map, str);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

    CU_ASSERT(cose_hdr_decode_from_cbor(buf, len, &header, key));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_TSTR);
    CU_ASSERT_EQUAL(memcmp(str,header.v.str, sizeof(str)), 0);
}

void test_hdr3(void)
{
    uint8_t str[] = "test string";
    int key = -4;
    CborEncoder enc, map;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_int(&map, key);
    cbor_encode_byte_string(&map, (uint8_t*)str, sizeof(str));
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

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
    CborParser p;
    CborValue it, imap;
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    CU_ASSERT_EQUAL(cose_hdr_encode_to_map(&header, &enc), 0);
    size_t len = nanocbor_encoded_len(&enc);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);

    int val;
    CU_ASSERT_EQUAL(cbor_value_is_integer(&imap), true);
    cbor_value_get_int(&imap, &val);
    CU_ASSERT_EQUAL(val, header.key);
    cbor_value_advance_fixed(&imap);
    CU_ASSERT_EQUAL(cbor_value_is_integer(&imap), true);
    cbor_value_get_int(&imap, &val);
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
    CborParser p;
    CborValue it, imap;
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    CU_ASSERT_EQUAL(cose_hdr_encode_to_map(&header, &enc), 0);
    size_t len = nanocbor_encoded_len(&enc);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);

    int val;
    const uint8_t *str;
    CU_ASSERT_EQUAL(cbor_value_is_integer(&imap), true);
    cbor_value_get_int(&imap, &val);
    CU_ASSERT_EQUAL(val, header.key);
    cbor_value_advance_fixed(&imap);
    CU_ASSERT_EQUAL(cbor_value_is_text_string(&imap), true);
    cose_cbor_get_string(&imap, &str, &len);
    CU_ASSERT_EQUAL(memcmp(str, header.v.str, len), 0);
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
    CborParser p;
    CborValue it, imap;
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, BUF_SIZE);
    nanocbor_fmt_map(&enc, 1);
    CU_ASSERT_EQUAL(cose_hdr_encode_to_map(&header, &enc), 0);
    size_t len = nanocbor_encoded_len(&enc);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);

    int val;
    const uint8_t *str;
    CU_ASSERT_EQUAL(cbor_value_is_integer(&imap), true);
    cbor_value_get_int(&imap, &val);
    CU_ASSERT_EQUAL(val, header.key);
    cbor_value_advance_fixed(&imap);
    CU_ASSERT_EQUAL(cbor_value_is_byte_string(&imap), true);
    cose_cbor_get_string(&imap, &str, &len);
    CU_ASSERT_EQUAL(memcmp(str, header.v.str, len), 0);
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
