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
#include <cn-cbor/cn-cbor.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static cn_cbor *_create_unprotected_direct(cose_recp_t *recp, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *map = cn_cbor_map_create(ct, errp);
    if (!map) {
        return false;
    }
    cn_cbor *cn_algo = cn_cbor_int_create(COSE_ALGO_DIRECT, ct, errp);
    CBOR_CATCH_ERR(cn_algo, map, ct);
    if(!cn_cbor_mapput_int(map, COSE_HDR_ALG, cn_algo, ct, errp)) {
        cn_cbor_free(cn_algo, ct);
        cn_cbor_free(map, ct);
        return NULL;
    }

    if (cose_key_unprotected_to_map(recp->key, map, ct, errp) < 0) {
        cn_cbor_free(map, ct);
        return NULL;
    }
    return map;
}

static bool _build_recp_direct(cose_recp_t *recp, cn_cbor *arr, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* Build an array with:
     * with zero length protected headers
     * Key ID and algo in the unprotected headers
     * zero length key field
     * And no further recipient structure as we don't have anything to encrypt */
    cn_cbor *cn_recp = cn_cbor_array_create(ct, errp);
    if (!cn_recp) {
        return false;
    }
    /* 0 length data for protected headers */
    cn_cbor *prot = cn_cbor_data_create(NULL, 0, ct, errp);
    if (!prot) {
        cn_cbor_free(cn_recp, ct);
        return false;
    }
    cn_cbor_array_append(cn_recp, prot, errp);

    /* unprotected headers with Key ID and Algo */
    cn_cbor *unprot = _create_unprotected_direct(recp, ct, errp);
    if (!unprot) {
        cn_cbor_free(cn_recp, ct);
        return false;
    }
    cn_cbor_array_append(cn_recp, unprot, errp);

    /* 0 Length data for this intermediate key (doesn't apply) */
    cn_cbor *key = cn_cbor_data_create(NULL, 0, ct, errp);
    if (!prot) {
        cn_cbor_free(cn_recp, ct);
        return false;
    }
    cn_cbor_array_append(cn_recp, key, errp);
    cn_cbor_array_append(arr, cn_recp, errp);
    return true;
}

cn_cbor *cose_recp_encrypt_to_map(cose_recp_t *recps, size_t num_recps,
                                  const uint8_t *cek, size_t ceklen,
                                  cn_cbor_context *ct,
                                  cn_cbor_errback *errp)
{
    cn_cbor *arr = cn_cbor_array_create(ct, errp);
    if (!arr) {
        return NULL;
    }
    cose_recp_t *parent_recp = NULL;
    /* Iterate over all recipients */
    for (unsigned i = 0; i < num_recps; i++) {
        cose_recp_t *cur_recp = &recps[i];
        if (cur_recp->parent == parent_recp) {
            /* Current target found */
            if (!ceklen) {
                /* No CEK to encrypt, direct assumed */
                if(!_build_recp_direct(cur_recp, arr, ct, errp)) {
                    cn_cbor_free(arr, ct);
                    return NULL;
                }
            }
            else {
                (void)cek;
//                _build_recp_cek(cur_recp, cek)
            }

        }
    }
    return arr;
}

