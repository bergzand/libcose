/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/* Shared recipient handling between MAC and Encrypt structs */
#include "cose.h"
#include "cose/intern.h"
#include <nanocbor/nanocbor.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static void _create_unprotected_direct(cose_recp_t *recp, nanocbor_encoder_t *enc)
{
    /* Algo and Kid */
    nanocbor_fmt_map(enc, 2);
    nanocbor_fmt_int(enc, COSE_HDR_ALG);
    nanocbor_fmt_int(enc, COSE_ALGO_DIRECT);
    cose_key_unprotected_to_map(recp->key, enc);
}

static bool _build_recp_direct(cose_recp_t *recp, nanocbor_encoder_t *arr)
{
    /* Build an array with:
     * with zero length protected headers
     * Key ID and algo in the unprotected headers
     * zero length key field
     * And no further recipient structure as we don't have anything to encrypt */
    nanocbor_fmt_array(arr, 3);
    /* 0 length data for protected headers */
    nanocbor_fmt_bstr(arr, 0);

    /* unprotected headers with Key ID and Algo */
    _create_unprotected_direct(recp, arr);

    /* 0 Length data for this intermediate key (doesn't apply) */
    nanocbor_fmt_bstr(arr, 0);
    return true;
}

size_t cose_recp_num_childs(cose_recp_t *recps, size_t num_recps, cose_recp_t *parent)
{
    size_t num = 0;
    for (size_t i = 0; i < num_recps; i++) {
        cose_recp_t *cur_recp = &recps[i];
        if (cur_recp->parent == parent) {
            num++;
        }
    }
    return num;
}

int cose_recp_encrypt_to_map(cose_recp_t *recps, size_t num_recps,
                                  const uint8_t *cek, size_t ceklen,
                                  nanocbor_encoder_t *enc)
{
    size_t num = cose_recp_num_childs(recps, num_recps, NULL);
    nanocbor_fmt_array(enc, num);
    cose_recp_t *parent_recp = NULL;
    /* Iterate over all recipients */
    for (size_t i = 0; i < num_recps; i++) {
        cose_recp_t *cur_recp = &recps[i];
        if (cur_recp->parent == parent_recp) {
            /* Current target found */
            if (!ceklen) {
                /* No CEK to encrypt, direct assumed */
                _build_recp_direct(cur_recp, enc);
            }
            else {
                (void)cek;
//                _build_recp_cek(cur_recp, cek)
            }

        }
    }
    return num;
}

void cose_recp_decode_init(cose_recp_dec_t *recp, const uint8_t *buf, size_t len)
{
    recp->buf = buf;
    recp->len = len;
}

int cose_recp_decode_protected(const cose_recp_dec_t *recp,
                                         cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *prot;
    size_t len = 0;
    if (cose_cbor_decode_get_prot(recp->buf, recp->len, &prot, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(prot, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

int cose_recp_decode_unprotected(const cose_recp_dec_t *recp,
                                           cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *unprot;
    size_t len = 0;
    if (cose_cbor_decode_get_unprot(recp->buf, recp->len, &unprot, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(unprot, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

int cose_recp_decode_ciphertext(const cose_recp_dec_t *recp, const uint8_t **sign, size_t *len)
{
    nanocbor_value_t arr;
    cose_cbor_decode_get_pos(recp->buf, recp->len, &arr, 2);
    if (nanocbor_get_null(&arr) == NANOCBOR_OK) {
        return COSE_ERR_NOT_FOUND;
    }
    if (nanocbor_get_bstr(&arr, sign, len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

int cose_recp_decode_recp(const cose_recp_dec_t *recp, const uint8_t **sign, size_t *len)
{
    nanocbor_value_t arr;
    cose_cbor_decode_get_pos(recp->buf, recp->len, &arr, 2);
    if (nanocbor_get_bstr(&arr, sign, len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}
