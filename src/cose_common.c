/*
 * Copyright (C) 2019 Koen Zandberg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose_defines.h"
#include "cose/common.h"

#include <nanocbor/nanocbor.h>

int cose_cbor_decode_get_pos(const uint8_t *start, size_t len,
                             nanocbor_value_t *arr,
                             unsigned idx)
{
    nanocbor_value_t p;
    nanocbor_decoder_init(&p, start, len);

    if (nanocbor_enter_array(&p, arr) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    for (unsigned i = 0; i < idx; i++) {
        if (nanocbor_skip(arr) < 0) {
            return COSE_ERR_INVALID_CBOR;
        }
    }
    return COSE_OK;
}

/* Retrieve protected headers from a structure */
int cose_cbor_decode_get_prot(const uint8_t *start, size_t len,
                              const uint8_t **prot, size_t *prot_len)
{
    nanocbor_value_t arr;

    if (cose_cbor_decode_get_pos(start, len, &arr, 0) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_bstr(&arr, prot, prot_len) < 0 ) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

/* Retrieve unprotected headers from a structure */
int cose_cbor_decode_get_unprot(const uint8_t *start, size_t len,
                                const uint8_t **unprot, size_t *unprot_len)
{
    nanocbor_value_t arr;

    if (cose_cbor_decode_get_pos(start, len, &arr, 1) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_subcbor(&arr, unprot, unprot_len) < 0 ) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}
