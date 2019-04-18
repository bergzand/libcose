/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose_defines.h"
#include "cose/common.h"
#include "cose/conf.h"
#include "cose/hdr.h"
#include "cose/intern.h"
#include "cose/key.h"
#include "cose/signature.h"
#include <nanocbor/nanocbor.h>
#include <stdint.h>
#include <string.h>

/**********************
 * encoding functions *
 **********************/
bool cose_signature_unprot_to_map(cose_signature_t *sig,
        nanocbor_encoder_t *map)
{
    cose_key_unprotected_to_map(sig->signer, map);
    if (cose_hdr_encode_to_map(sig->hdrs.unprot, map)) {
        return false;
    }
    return true;
}

int cose_signature_unprot_cbor(cose_signature_t *sig,
        nanocbor_encoder_t *enc)
{
    /* Increment to also contain KID */
    size_t len = cose_hdr_size(sig->hdrs.unprot) + 1;
    nanocbor_fmt_map(enc, len);
    return cose_signature_unprot_to_map(sig, enc);
}

void cose_signature_prot_to_map(const cose_signature_t *sig,
        nanocbor_encoder_t *map, bool encode)
{
    if (encode) {
        cose_key_protected_to_map(sig->signer, map);
    }
    cose_hdr_encode_to_map(sig->hdrs.prot, map);
}

size_t cose_signature_serialize_protected(const cose_signature_t *sig,
        bool encode, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;

    /* Also contains algo */
    size_t len = cose_hdr_size(sig->hdrs.prot);
    len += encode ? 1 : 0;

    nanocbor_encoder_init(&enc, buf, buflen);
    nanocbor_fmt_map(&enc, len);
    cose_signature_prot_to_map(sig, &enc, encode);

    return nanocbor_encoded_len(&enc);
}

bool cose_signature_get_header(cose_signature_t *signature, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get(&signature->hdrs, hdr, key);
}

bool cose_signature_get_protected(cose_signature_t *signature, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get_protected(&signature->hdrs, hdr, key);
}

bool cose_signature_get_unprotected(cose_signature_t *signature, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get_unprotected(&signature->hdrs, hdr, key);
}

size_t cose_signature_num(cose_signature_t *signature)
{
    size_t res = 0;
    for(; signature; signature = signature->next)
    {
        res++;
    }
    return res;
}

/**********************
 * decoding functions *
 **********************/

void cose_signature_decode_init(cose_signature_dec_t *signature, const uint8_t *buf, size_t len)
{
    signature->buf = buf;
    signature->len = len;
}

int cose_signature_decode_protected(const cose_signature_dec_t *signature,
                                         cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *prot;
    size_t len = 0;
    if (cose_cbor_decode_get_prot(signature->buf, signature->len, &prot, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(prot, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}
int cose_signature_decode_unprotected(const cose_signature_dec_t *signature,
                                           cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *unprot;
    size_t len = 0;
    if (cose_cbor_decode_get_unprot(signature->buf, signature->len, &unprot, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(unprot, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

int cose_signature_decode_signature(const cose_signature_dec_t *signature, const uint8_t **sign, size_t *len)
{
    nanocbor_value_t arr;
    cose_cbor_decode_get_pos(signature->buf, signature->len, &arr, 2);
    if (nanocbor_get_bstr(&arr, sign, len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

COSE_ssize_t cose_signature_decode_kid(const cose_signature_dec_t *signature, const uint8_t **kid)
{
    *kid = NULL;
    cose_hdr_t hdr;
    int res = cose_signature_decode_protected(signature, &hdr, COSE_HDR_KID);
    if (res < 0) {
        res = cose_signature_decode_unprotected(signature, &hdr, COSE_HDR_KID);
    }
    if (res < 0) {
        return res;
    }
    if (hdr.type != COSE_HDR_TYPE_BSTR) {
        return COSE_ERR_INVALID_CBOR;
    }
    *kid = hdr.v.data;
    return hdr.len;
}
