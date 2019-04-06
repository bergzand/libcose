/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose_defines.h"
#include "cose/conf.h"
#include "cose/crypto.h"
#include "cose/hdr.h"
#include "cose/intern.h"
#include "cose/key.h"
#include "cose/sign.h"
#include "cose/signature.h"
#include <nanocbor/nanocbor.h>
#include <stdint.h>
#include <string.h>

#define COSE_SIGN_SIG_SIGN1_LEN     4U
#define COSE_SIGN_SIG_SIGN_LEN      5U

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen);
static void _sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, nanocbor_encoder_t *enc);
static size_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buflen);
static int _cbor_unprotected(cose_sign_t *sign, nanocbor_encoder_t *enc);
static void _place_cbor_protected(cose_sign_t *sign, nanocbor_encoder_t *arr);

static void _sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, nanocbor_encoder_t *enc)
{
    size_t len = _is_sign1(sign) ? COSE_SIGN_SIG_SIGN1_LEN
                                 : COSE_SIGN_SIG_SIGN_LEN;
    nanocbor_fmt_array(enc, len);

    /* Add type string */
    nanocbor_put_tstr(enc, type);

    /* Add body protected headers */
    _place_cbor_protected(sign, enc);

    /* Add signer protected headers */
    if (!_is_sign1(sign)) {
        if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
            size_t slen = cose_signature_serialize_protected(sig, true, NULL, 0);
            nanocbor_put_bstr(enc, enc->cur, slen);
            cose_signature_serialize_protected(sig, true, enc->cur - slen, slen);
        }
        else {
            nanocbor_put_bstr(enc, sig->hdrs.prot.b, sig->hdrs.prot_len);
        }
    }

    /* External aad */
    nanocbor_put_bstr(enc, sign->ext_aad, sign->ext_aad_len);

    /* Add payload */
    nanocbor_put_bstr(enc, sign->payload, sign->payload_len);
}

static size_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buflen);
    _sign_sig_cbor(sign, sig, type, &enc);
    return nanocbor_encoded_len(&enc);
}

static int _cbor_unprotected(cose_sign_t *sign, nanocbor_encoder_t *enc)
{
    size_t len = cose_hdr_size(sign->hdrs.unprot.c);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->signatures->hdrs.unprot.c) + 1;
    }
    nanocbor_fmt_map(enc, len);
    cose_hdr_add_to_map(sign->hdrs.unprot.c, enc);
    if (_is_sign1(sign)) {
        cose_signature_unprot_to_map(sign->signatures, enc);
    }
    return 0;
}

static int _cbor_protected(cose_sign_t *sign, nanocbor_encoder_t *enc)
{
    size_t len = cose_hdr_size(sign->hdrs.prot.c);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->signatures->hdrs.prot.c);
        len += cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE) ? 1 : 0;
    }
    nanocbor_fmt_map(enc, len);

    cose_hdr_add_to_map(sign->hdrs.prot.c, enc);
    if (_is_sign1(sign)) {
        if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
            cose_key_protected_to_map(sign->signatures->signer, enc);
        }
        cose_hdr_add_to_map(sign->signatures->hdrs.prot.c, enc);
    }
    return 0;
}

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buflen);
    _cbor_protected(sign, &enc);
    return nanocbor_encoded_len(&enc);
}

static void _place_cbor_protected(cose_sign_t *sign, nanocbor_encoder_t *arr)
{
    if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
        size_t slen = _serialize_cbor_protected(sign, NULL, 0);
        nanocbor_put_bstr(arr, arr->cur, slen);
        _serialize_cbor_protected(sign, arr->cur - slen, slen);
    }
    else {
        nanocbor_put_bstr(arr, sign->hdrs.prot.b, sign->hdrs.prot_len);
    }
}

static int _add_signatures(cose_sign_t *sign, nanocbor_encoder_t *arr)
{
    for (cose_signature_t *sig = sign->signatures; sig; sig = sig->next) {
        if (sig->signature_len) {
            /* Construct the array */
            nanocbor_fmt_array(arr, 3);

            size_t slen = cose_signature_serialize_protected(sig, true, NULL, 0);
            nanocbor_put_bstr(arr, arr->cur, slen);
            cose_signature_serialize_protected(sig, true, arr->cur - slen, slen);
            /* Add unprotected headers to the signature struct */
            cose_signature_unprot_cbor(sig, arr);
            /* Add signature space */
            nanocbor_put_bstr(arr, sig->signature, sig->signature_len);
        }
    }
    return COSE_OK;
}

void cose_sign_init(cose_sign_t *sign, uint16_t flags)
{
    memset(sign, 0, sizeof(cose_sign_t));
    sign->flags = flags;
}

void cose_sign_set_payload(cose_sign_t *sign, const void *payload, size_t len)
{
    sign->payload = payload;
    sign->payload_len = len;
}

void cose_sign_get_payload(cose_sign_t *sign, const uint8_t **payload,
                           size_t *len)
{
    *payload = (const uint8_t*)sign->payload;
    *len = sign->payload_len;
}

void cose_sign_add_signer(cose_sign_t *sign, cose_signature_t *signer, const cose_key_t *key)
{
    signer->next = sign->signatures;
    sign->signatures = signer;
    signer->signer = key;
}

int cose_sign_generate_signature(cose_sign_t *sign, cose_signature_t *sig, uint8_t *buf, size_t len)
{
    uint8_t *buf_cbor = buf + cose_crypto_sig_size(sig->signer);
    size_t cbor_space = len - cose_crypto_sig_size(sig->signer);

    if (!sig->signer) {
        return COSE_ERR_NOINIT;
    }
    /* Build the data at an offset of the signature size */
    size_t sig_struct_len = _sign_sig_encode(sign, sig,
                                             _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                             buf_cbor, cbor_space);
    int res = cose_crypto_sign(sig->signer, buf, &(sig->signature_len), buf_cbor, sig_struct_len);
    /* Store pointer to the signature */
    sig->signature = buf;
    return res;
}

COSE_ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t len, uint8_t **out)
{
    /* The buffer here is used to contain dummy data a number of times */
    nanocbor_encoder_t enc;

    sign->flags |= COSE_FLAGS_ENCODE;

    if (!sign->signatures) {
        return COSE_ERR_INVALID_PARAM;
    }
    /* Determine if this requires sign or sign1 */
    if (!sign->signatures->next) {
        sign->flags |= COSE_FLAGS_SIGN1;
    }

    /* First generate all required signatures */
    for (cose_signature_t *sig = sign->signatures; sig; sig = sig->next) {
        /* Start generating the signature */
        int res = cose_sign_generate_signature(sign, sig, buf, len);
        if (res != COSE_OK) {
            return res;
        }
        buf += sig->signature_len;
        len -= sig->signature_len;
    }

    nanocbor_encoder_init(&enc, buf, len);
    /* Build tag */
    if (!(cose_flag_isset(sign->flags, COSE_FLAGS_UNTAGGED))) {
        nanocbor_fmt_tag(&enc,
            _is_sign1(sign) ? COSE_SIGN1 : COSE_SIGN);
    }
    /* Create the main array */
    nanocbor_fmt_array(&enc, 4);

    /* Create protected body header bstr */
    _place_cbor_protected(sign, &enc);

    /* Create unprotected body header map */
    _cbor_unprotected(sign, &enc);

    /* Create payload */
    if (cose_flag_isset(sign->flags, COSE_FLAGS_EXTDATA)) {
        nanocbor_put_bstr(&enc, NULL, 0);
    }
    else {
        nanocbor_put_bstr(&enc, sign->payload, sign->payload_len);
    }

    /* Now use the signatures to add to the signature array, still nonsense in the protected headers */
    if (_is_sign1(sign)) {
        nanocbor_put_bstr(&enc, sign->signatures->signature, sign->signatures->signature_len);
    }
    else {
        /* Create the signature array */
        nanocbor_fmt_array(&enc, cose_signature_num(sign->signatures));
        _add_signatures(sign, &enc);
    }

    *out = buf;
    size_t res;
    if (nanocbor_encoded_len(&enc) > len) {
        res = COSE_ERR_NOMEM;
    }
    else {
        res = nanocbor_encoded_len(&enc);
    }
    return res;
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len)
{
    nanocbor_value_t p;
    nanocbor_value_t arr;

    nanocbor_decoder_init(&p, buf, len);
    sign->flags |= COSE_FLAGS_DECODE;

    /* Check tag values */
    if (nanocbor_get_type(&p) == NANOCBOR_TYPE_TAG) {
        nanocbor_skip_simple(&p);
    }

    if (nanocbor_enter_array(&p, &arr) < 0 ||
            nanocbor_container_remaining(&arr) != 4) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_bstr(&arr, &sign->hdrs.prot.b, &sign->hdrs.prot_len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_type(&arr) !=  NANOCBOR_TYPE_MAP) {
        return COSE_ERR_INVALID_CBOR;
    }

    sign->hdrs.unprot.b = arr.start;

    nanocbor_skip(&arr);

    sign->hdrs.unprot_len = arr.start - sign->hdrs.unprot.b;

    nanocbor_get_bstr(&arr, (const uint8_t **)&sign->payload, &sign->payload_len);

    if (!sign->payload_len) {
        /* Zero payload length, thus external payload */
        sign->flags |= COSE_FLAGS_EXTDATA;
        sign->payload = NULL;
    }

    sign->sig = arr.start;
    if (nanocbor_get_type(&arr) == NANOCBOR_TYPE_BSTR) {
        sign->flags |= COSE_FLAGS_SIGN1;
    }
    nanocbor_skip(&arr);
    sign->sig_len = arr.start - sign->sig;

    return COSE_OK;
}

void cose_sign_iter_init(cose_sign_t *sign, cose_sign_iter_t *iter)
{
    iter->sign = sign;
    nanocbor_decoder_init(&iter->it, sign->sig, sign->sig_len);
    if (nanocbor_enter_array(&iter->it, &iter->arr) < 0) {
        iter->arr = iter->it;
    }
}

bool cose_sign_iter(cose_sign_iter_t *iter, cose_signature_t *signature)
{
    bool res = false;
    if (!nanocbor_at_end(&iter->arr)) {
        if (nanocbor_get_type(&iter->it) == NANOCBOR_TYPE_BSTR) {
            /* Sign1 */
            signature->hdrs.prot.b = iter->sign->hdrs.prot.b;
            signature->hdrs.prot_len = iter->sign->hdrs.prot_len;
            signature->hdrs.unprot.b = iter->sign->hdrs.unprot.b;
            signature->hdrs.unprot_len = iter->sign->hdrs.unprot_len;
            nanocbor_get_bstr(&iter->arr, &signature->signature,
                    &signature->signature_len);
            res = true;
        }
        else if (nanocbor_get_type(&iter->it) == NANOCBOR_TYPE_ARR) {
            res = cose_signature_decode(signature, &iter->arr);
        }
    }
    return res;
}

bool cose_sign_get_header(cose_sign_t *sign, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get(&sign->hdrs, hdr, key);
}

bool cose_sign_get_protected(cose_sign_t *sign, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get_protected(&sign->hdrs, hdr, key);
}

bool cose_sign_get_unprotected(cose_sign_t *sign, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get_unprotected(&sign->hdrs, hdr, key);
}

/* Try to verify the structure with a signer and a signature idx */
int cose_sign_verify(cose_sign_t *sign, cose_signature_t *signature, cose_key_t *key, uint8_t *buf, size_t len)
{
    int res = COSE_OK;
    const cose_key_t *tmp = signature->signer;
    signature->signer = key;
    COSE_ssize_t sig_len = _sign_sig_encode(sign, signature,
                                       _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                       buf, len);
    if (sig_len < 0) {
        return (int)sig_len;
    }
    if (cose_crypto_verify(key, signature->signature, signature->signature_len, buf, sig_len) < 0) {
        res = COSE_ERR_CRYPTO;
    }
    signature->signer = tmp;
    return res;
}

int cose_sign_verify_first(cose_sign_t* sign, cose_key_t *key, uint8_t *buf, size_t len)
{
    cose_sign_iter_t iter;
    cose_signature_t signature;
    cose_sign_iter_init(sign, &iter);
    if (!cose_sign_iter(&iter, &signature)) {
        return COSE_ERR_INVALID_CBOR;
    }
    return cose_sign_verify(sign, &signature, key, buf, len);
}

