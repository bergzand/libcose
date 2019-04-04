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
#include <cbor.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static void _create_unprotected_direct(cose_recp_t *recp, CborEncoder *enc)
{
    CborEncoder map;
    /* Algo and Kid */
    cbor_encoder_create_map(enc, &map, 2);
    cbor_encode_int(&map, COSE_HDR_ALG);
    cbor_encode_int(&map, COSE_ALGO_DIRECT);
    cose_key_unprotected_to_map(recp->key, &map);
    cbor_encoder_close_container(enc, &map);
}

static bool _build_recp_direct(cose_recp_t *recp, CborEncoder *arr)
{
    /* Build an array with:
     * with zero length protected headers
     * Key ID and algo in the unprotected headers
     * zero length key field
     * And no further recipient structure as we don't have anything to encrypt */
    CborEncoder cb_recp;
    cbor_encoder_create_array(arr, &cb_recp, 3);
    /* 0 length data for protected headers */
    cbor_encode_byte_string(&cb_recp, NULL, 0);

    /* unprotected headers with Key ID and Algo */
    _create_unprotected_direct(recp, &cb_recp);

    /* 0 Length data for this intermediate key (doesn't apply) */
    cbor_encode_byte_string(&cb_recp, NULL, 0);
    cbor_encoder_close_container(arr, &cb_recp);
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
                                  CborEncoder *enc)
{
    CborEncoder arr;
    size_t num = cose_recp_num_childs(recps, num_recps, NULL);
    cbor_encoder_create_array(enc, &arr, num);
    cose_recp_t *parent_recp = NULL;
    /* Iterate over all recipients */
    for (size_t i = 0; i < num_recps; i++) {
        cose_recp_t *cur_recp = &recps[i];
        if (cur_recp->parent == parent_recp) {
            /* Current target found */
            if (!ceklen) {
                /* No CEK to encrypt, direct assumed */
                _build_recp_direct(cur_recp, &arr);
            }
            else {
                (void)cek;
//                _build_recp_cek(cur_recp, cek)
            }

        }
    }
    cbor_encoder_close_container(enc, &arr);
    return num;
}

