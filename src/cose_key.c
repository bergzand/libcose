/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include "cose.h"
#include "cose/intern.h"
#include <cn-cbor/cn-cbor.h>
#include <stdint.h>
#include <string.h>


int _get_algo(const cose_key_t *key)
{
    /* TODO: make configurable, P$NUM and ES$NUM don't have to match */
    int res = 0;

    switch (key->crv) {
        case COSE_EC_CURVE_P256:
            res = COSE_ALGO_ES256;
            break;
        case COSE_EC_CURVE_P384:
            res = COSE_ALGO_ES384;
            break;
        case COSE_EC_CURVE_P521:
            res = COSE_ALGO_ES512;
            break;
        case COSE_EC_CURVE_ED448:
            res = COSE_ALGO_EDDSA;
            break;
        case COSE_EC_CURVE_ED25519:
            res = COSE_ALGO_EDDSA;
            break;
        default:
            res = 0;
    }
    return res;
}

void cose_key_init(cose_key_t *key)
{
    memset(key, 0, sizeof(cose_key_t));
}

void cose_key_set_keys(cose_key_t *key, cose_curve_t curve,
                          uint8_t *x, uint8_t *y, uint8_t *d)
{
    /* Add support for more signing types as soon as they are required */
    if ((curve == COSE_EC_CURVE_P256) ||
        (curve == COSE_EC_CURVE_P384) ||
        (curve == COSE_EC_CURVE_P521)) {
        key->kty = COSE_KTY_EC2;
    }
    else {
        key->kty = COSE_KTY_OCTET;
    }
    key->crv = curve;
    key->x = x;
    key->y = y;
    key->d = d;
}

void cose_key_set_kid(cose_key_t *key, uint8_t *kid, size_t len)
{
    key->kid = kid;
    key->kid_len = len;
}

int cose_key_protected_to_map(const cose_key_t *key, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_algo = cn_cbor_int_create(_get_algo(key), ct, errp);

    if (!cn_algo) {
        return -1;
    }
    if (!(cn_cbor_mapput_int(map, COSE_HDR_ALG, cn_algo, ct, errp))) {
        cn_cbor_free(cn_algo, ct);
        return -1;
    }
    return 0;
}

int cose_key_unprotected_to_map(const cose_key_t *key, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_kid = cn_cbor_data_create(key->kid, key->kid_len, ct, errp);

    if (!cn_kid) {
        return -1;
    }

    if (!(cn_cbor_mapput_int(map, COSE_HDR_KID, cn_kid, ct, errp))) {
        cn_cbor_free(cn_kid, ct);
        return -1;
    }
    return 0;
}
