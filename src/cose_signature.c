/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose_defines.h"
#include "cose/cbor.h"
#include "cose/conf.h"
#include "cose/hdr.h"
#include "cose/intern.h"
#include "cose/key.h"
#include "cose/signature.h"
#include <cbor.h>
#include <stdint.h>
#include <string.h>

bool cose_signature_unprot_to_map(cose_signature_t *sig,
        CborEncoder *map)
{
    cose_key_unprotected_to_map(sig->signer, map);
    if (cose_hdr_add_to_map(sig->hdrs.unprot.c, map)) {
        return false;
    }
    return true;
}

CborError cose_signature_unprot_cbor(cose_signature_t *sig,
        CborEncoder *enc)
{
    CborEncoder map;
    /* Increment to also contain KID */
    size_t len = cose_hdr_size(sig->hdrs.unprot.c) + 1;
    cbor_encoder_create_map(enc, &map, len);
    CborError res = cose_signature_unprot_to_map(sig, &map);
    cbor_encoder_close_container(enc, &map);
    return res;
}

void cose_signature_prot_to_map(const cose_signature_t *sig,
        CborEncoder *map, bool encode)
{
    if (encode) {
        cose_key_protected_to_map(sig->signer, map);
    }
    cose_hdr_add_to_map(sig->hdrs.prot.c, map);
}

size_t cose_signature_serialize_protected(const cose_signature_t *sig,
        bool encode, uint8_t *buf, size_t buflen)
{
    CborEncoder enc, map;

    /* Also contains algo */
    size_t len = cose_hdr_size(sig->hdrs.prot.c);
    len += encode ? 1 : 0;

    cbor_encoder_init(&enc, buf, buflen, 0);
    cbor_encoder_create_map(&enc, &map, len);
    cose_signature_prot_to_map(sig, &map, encode);
    cbor_encoder_close_container(&enc, &map);

    if (!buflen) {
        return cbor_encoder_get_extra_bytes_needed(&enc);
    }
    return cbor_encoder_get_buffer_size(&enc, buf);
}

bool cose_signature_decode(cose_signature_t *signature, CborValue *arr)
{
    CborValue sig;
    cbor_value_enter_container(arr, &sig);

    /* Protected headers */
    cose_cbor_get_string(&sig, &signature->hdrs.prot.b, &signature->hdrs.prot_len);

    /* Unprotected headers */
    cbor_value_advance(&sig);
    signature->hdrs.unprot.b = sig.ptr;

    /* Signature */
    cbor_value_advance(&sig);
    signature->hdrs.unprot_len = sig.ptr - signature->hdrs.unprot.b;
    cose_cbor_get_string(&sig, &signature->signature, &signature->signature_len);
    return true;
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

COSE_ssize_t cose_signature_get_kid(cose_signature_t *signature, const uint8_t **kid)
{
    *kid = NULL;
    cose_hdr_t hdr;
    if (cose_hdr_get(&signature->hdrs, &hdr, COSE_HDR_KID)) {
        *kid = hdr.v.data;
        return hdr.len;
    }
    return COSE_ERR_NOT_FOUND;
}
