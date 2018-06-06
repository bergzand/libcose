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

#ifdef HAVE_ALGO_CHACHA20POLY1305
static uint8_t chachakey[] = { 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0, 0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x88, 0x97, 0xA6, 0xB5, 0xC4, 0xD3, 0xE2, 0xF1, 0x00 };
static uint8_t buf[2048];
static uint8_t plaintext[2048];
static uint8_t nonce[12U] = {0x26, 0x68, 0x23, 0x06, 0xd4, 0xfb, 0x28, 0xca, 0x01, 0xb4, 0x3b, 0x80};
static uint8_t payload[] = "This is the content.";

static uint8_t kid[] = "sec-256";

static void print_bytestr(const uint8_t *bytes, size_t len)
{
    for(unsigned int idx=0; idx < len; idx++)
    {
        printf("%02X", bytes[idx]);
    }
}
#endif


/* Tagged 1 encrypt test with chacha20poly1305*/
#ifdef HAVE_ALGO_CHACHA20POLY1305
void test_encrypt1(void)
{
    uint8_t *out;
    printf("Using nonce: ");
    print_bytestr(nonce, sizeof(nonce));
    printf("\n");
    cose_encrypt_t crypt, decrypt;
    cose_key_t key;
    cose_encrypt_init(&crypt);
    cose_encrypt_init(&decrypt);
    cose_key_init(&key);
    cose_key_set_kid(&key, kid, sizeof(kid) - 1);
    cose_key_set_keys(&key, 0, COSE_ALGO_CHACHA20POLY1305, NULL, NULL, chachakey);
    cose_encrypt_add_recipient(&crypt, &key);
    cose_encrypt_set_payload(&crypt, payload, sizeof(payload)-1);
    cose_encrypt_set_algo(&crypt, COSE_ALGO_DIRECT);
    COSE_ssize_t len = cose_encrypt_encode(&crypt, buf, sizeof(buf), nonce, &out);
    if (len > 0) {
        print_bytestr(out, len);
        printf("\n");
    }
    CU_ASSERT_NOT_EQUAL_FATAL(len, 0);
    CU_ASSERT_EQUAL(cose_encrypt_decode(&decrypt, out, len), 0);
    size_t plaintext_len = 0;
    CU_ASSERT_EQUAL(cose_encrypt_decrypt(&decrypt, &key, 0, buf, sizeof(buf), plaintext, &plaintext_len), 0);
    CU_ASSERT_EQUAL(plaintext_len, sizeof(payload)-1);
}
#endif

const test_t tests_encrypt[] = {
#ifdef HAVE_ALGO_CHACHA20POLY1305
    {
        .f = test_encrypt1,
        .n = "Encryption with 1 recipient",
    },
#endif
    {
        .f = NULL,
        .n = NULL,
    }
};
