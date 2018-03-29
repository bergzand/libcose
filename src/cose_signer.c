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


int _get_algo(const cose_signer_t *signer)
{
    /* TODO: make configurable, P$NUM and ES$NUM don't have to match */
    int res = 0;

    switch (signer->crv) {
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

void cose_signer_init(cose_signer_t *signer)
{
    memset(signer, 0, sizeof(cose_signer_t));
}

void cose_signer_set_keys(cose_signer_t *signer, cose_curve_t curve,
                          uint8_t *x, uint8_t *y, uint8_t *d)
{
    /* Add support for more signing types as soon as they are required */
    if ((curve == COSE_EC_CURVE_P256) ||
        (curve == COSE_EC_CURVE_P384) ||
        (curve == COSE_EC_CURVE_P521)) {
        signer->kty = COSE_KTY_EC2;
    }
    else {
        signer->kty = COSE_KTY_OCTET;
    }
    signer->crv = curve;
    signer->x = x;
    signer->y = y;
    signer->d = d;
}

void cose_signer_set_kid(cose_signer_t *signer, uint8_t *kid, size_t len)
{
    signer->kid = kid;
    signer->kid_len = len;
}

size_t cose_signer_serialize_protected(const cose_signer_t *signer, uint8_t *buf, size_t len, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    size_t res = 0;
    cn_cbor *cn_prot = cose_signer_cbor_protected(signer, ct, errp);

    if (cn_prot) {
        res = cn_cbor_encoder_write(buf, 0, len, cn_prot);
        cn_cbor_free(cn_prot, ct);
    }
    return res;
}

int cose_signer_protected_to_map(const cose_signer_t *signer, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_algo = cn_cbor_int_create(_get_algo(signer), ct, errp);

    if (!cn_algo) {
        return -1;
    }
    if (!(cn_cbor_mapput_int(map, COSE_HDR_ALG, cn_algo, ct, errp))) {
        cn_cbor_free(cn_algo, ct);
        return -1;
    }
    return 0;
}

cn_cbor *cose_signer_cbor_protected(const cose_signer_t *signer, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* TODO: add key restriction hdr */
    cn_cbor *cn_map = cn_cbor_map_create(ct, errp);

    if (!cn_map) {
        return NULL;
    }
    if (cose_signer_protected_to_map(signer, cn_map, ct, errp) < 0) {
        cn_cbor_free(cn_map, ct);
        return NULL;
    }
    return cn_map;
}

int cose_signer_unprotected_to_map(const cose_signer_t *signer, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_kid = cn_cbor_data_create(signer->kid, signer->kid_len, ct, errp);

    if (!cn_kid) {
        return -1;
    }

    if (!(cn_cbor_mapput_int(map, COSE_HDR_KID, cn_kid, ct, errp))) {
        cn_cbor_free(cn_kid, ct);
        return -1;
    }
    return 0;
}

cn_cbor *cose_signer_cbor_unprotected(const cose_signer_t *signer, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_map = cn_cbor_map_create(ct, errp);

    if (!cn_map) {
        return NULL;
    }
    if (cose_signer_unprotected_to_map(signer, cn_map, ct, errp) < 0) {
        cn_cbor_free(cn_map, ct);
        return NULL;
    }
    return cn_map;
}
