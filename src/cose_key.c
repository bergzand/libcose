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
#include <cbor.h>
#include <stdint.h>
#include <string.h>


void cose_key_init(cose_key_t *key)
{
    memset(key, 0, sizeof(cose_key_t));
}

void cose_key_set_keys(cose_key_t *key, cose_curve_t curve, cose_algo_t algo,
                          uint8_t *x, uint8_t *y, uint8_t *d)
{
    /* Add support for more key types as soon as they are required */
    switch(curve)
    {
        case COSE_EC_CURVE_P256:
        case COSE_EC_CURVE_P384:
        case COSE_EC_CURVE_P521:
            key->kty = COSE_KTY_EC2;
            break;
        case COSE_EC_CURVE_X25519:
        case COSE_EC_CURVE_X448:
        case COSE_EC_CURVE_ED25519:
        case COSE_EC_CURVE_ED448:
            key->kty = COSE_KTY_OCTET;
            break;
        default:
            key->kty = COSE_KTY_SYMM;
    }
    key->crv = curve;
    /* TODO: verify matching curve/algo pair */
    key->algo = algo;
    key->x = x;
    key->y = y;
    key->d = d;
}

void cose_key_set_kid(cose_key_t *key, uint8_t *kid, size_t len)
{
    key->kid = kid;
    key->kid_len = len;
}

void cose_key_protected_to_map(const cose_key_t *key, CborEncoder *map)
{
    cbor_encode_int(map, COSE_HDR_ALG);
    cbor_encode_int(map, key->algo);
}

void cose_key_unprotected_to_map(const cose_key_t *key, CborEncoder *map)
{
    cbor_encode_int(map, COSE_HDR_KID);
    cbor_encode_byte_string(map, key->kid, key->kid_len);
}
