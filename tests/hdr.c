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
#include <cbor.h>
#include <cose/cbor.h>
#include <CUnit/CUnit.h>

#define HDRS_SIZE   4

#define BUF_SIZE    128
static uint8_t buf[BUF_SIZE];

void test_hdr1(void)
{
    int val = 3278;
    int key = 5734;
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_int(&map, key);
    cbor_encode_int(&map, val);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);
    CU_ASSERT(cose_hdr_from_cbor_map(&header, &imap));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_INT);
    CU_ASSERT_EQUAL(header.v.value, val);
}

void test_hdr2(void)
{
    char str[] = "test string";
    int key = 5734;
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_int(&map, key);
    cbor_encode_text_stringz(&map, str);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);

    CU_ASSERT(cose_hdr_from_cbor_map(&header, &imap));
    CU_ASSERT_EQUAL(header.key, key);
    CU_ASSERT_EQUAL(header.type, COSE_HDR_TYPE_TSTR);
    CU_ASSERT_EQUAL(memcmp(str,header.v.str, sizeof(str)), 0);
}

void test_hdr3(void)
{
    uint8_t str[] = "test string";
    int key = -4;
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_int(&map, key);
    cbor_encode_byte_string(&map, (uint8_t*)str, sizeof(str));
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);

    CU_ASSERT(cose_hdr_from_cbor_map(&header, &imap));
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
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    CU_ASSERT_EQUAL(cose_hdr_to_cbor_map(&header, &map), 0);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

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
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    CU_ASSERT_EQUAL(cose_hdr_to_cbor_map(&header, &map), 0);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

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
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    CU_ASSERT_EQUAL(cose_hdr_to_cbor_map(&header, &map), 0);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

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

void test_hdr9(void)
{
    char str[] = "test string";
    CborEncoder enc, map;
    CborParser p;
    CborValue it, imap;
    cose_hdr_t header;

    cbor_encoder_init(&enc, buf, BUF_SIZE, 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_text_stringz(&map, str);
    cbor_encoder_close_container(&enc, &map);
    size_t len = cbor_encoder_get_buffer_size(&enc, buf);

    cbor_parser_init(buf, len, 0, &p, &it);
    cbor_value_enter_container(&it, &imap);

    CU_ASSERT_FALSE(cose_hdr_from_cbor_map(&header, &imap));
}

void test_hdr10(void)
{
    cose_hdr_t hdrs[HDRS_SIZE];
    char test_input[] = "data";
    memset(hdrs, 0, sizeof(hdrs));
    /* Fill the array */
    CU_ASSERT_EQUAL(cose_hdr_add_hdr_value(hdrs, HDRS_SIZE, 1, 0, 1), 0);
    CU_ASSERT_EQUAL(cose_hdr_add_hdr_string(hdrs, HDRS_SIZE, 2, 0, test_input), 0);
    CU_ASSERT_EQUAL(cose_hdr_add_hdr_data(hdrs, HDRS_SIZE, 3, 0, (uint8_t*)test_input, sizeof(test_input)), 0);
    CU_ASSERT_EQUAL(cose_hdr_add_hdr_value(hdrs, HDRS_SIZE, 1, 0, 1), 0);

    /* Array should be full now */
    CU_ASSERT_NOT_EQUAL(cose_hdr_add_hdr_value(hdrs, HDRS_SIZE, 5, 0, 1), 0);
    CU_ASSERT_NOT_EQUAL(cose_hdr_add_hdr_string(hdrs, HDRS_SIZE, 6, 0, test_input), 0);
    CU_ASSERT_NOT_EQUAL(cose_hdr_add_hdr_data(hdrs, HDRS_SIZE, 7, 0, (uint8_t*)test_input, sizeof(test_input)), 0);
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
        .f = test_hdr9,
        .n = "Invalid header conversion to CBOR",
    },
    {
        .f = test_hdr10,
        .n = "Header additions Out of memory",
    },
    {
        .f = NULL,
        .n = NULL,
    }
};
