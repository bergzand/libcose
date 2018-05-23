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
#include "cose/crypto.h"
#include "cose/hdr.h"
#include "cose/intern.h"
#include "cose/key.h"
#include "cose/sign.h"
#include "cose/signature.h"
#include <cbor.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen);
static void _sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, CborEncoder *enc);
static size_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buflen);
static CborError _cbor_unprotected(cose_sign_t *sign, CborEncoder *enc);
static void _place_cbor_protected(cose_sign_t *sign, CborEncoder *arr);

static void _sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, CborEncoder *enc)
{
    CborEncoder arr;
    size_t len = _is_sign1(sign) ? 4 : 5;
    cbor_encoder_create_array(enc, &arr, len);

    /* Add type string */
    cbor_encode_text_stringz(&arr, type);

    /* Add body protected headers */
    _place_cbor_protected(sign, &arr);

    /* Add signer protected headers */
    if (!_is_sign1(sign)) {
        if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
            size_t slen = cose_signature_serialize_protected(sig, true, NULL, 0);
            cbor_encode_byte_string(&arr, arr.data.ptr, slen);
            cose_signature_serialize_protected(sig, true, arr.data.ptr - slen, slen);
        }
        else {
            cbor_encode_byte_string(&arr, sig->hdrs.prot.b, sig->hdrs.prot_len);
        }
    }

    /* External aad */
    cbor_encode_byte_string(&arr, sign->ext_aad, sign->ext_aad_len);

    /* Add payload */
    cbor_encode_byte_string(&arr, sign->payload, sign->payload_len);
    cbor_encoder_close_container(enc, &arr);
}

static size_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buflen)
{
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buflen, 0);
    _sign_sig_cbor(sign, sig, type, &enc);
    if (!buflen) {
        return cbor_encoder_get_extra_bytes_needed(&enc);
    }
    return cbor_encoder_get_buffer_size(&enc, buf);
}

static CborError _cbor_unprotected(cose_sign_t *sign, CborEncoder *enc)
{
    CborEncoder map;
    size_t len = cose_hdr_size(sign->hdrs.unprot.c);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->signatures->hdrs.unprot.c) + 1;
    }
    cbor_encoder_create_map(enc, &map, len);
    cose_hdr_add_to_map(sign->hdrs.unprot.c, &map);
    if (_is_sign1(sign)) {
        cose_signature_unprot_to_map(sign->signatures, &map);
    }
    cbor_encoder_close_container(enc, &map);
    return 0;
}

static CborError _cbor_protected(cose_sign_t *sign, CborEncoder *enc)
{
    CborEncoder map;
    size_t len = cose_hdr_size(sign->hdrs.prot.c);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->signatures->hdrs.prot.c);
        len += cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE) ? 1 : 0;
    }
    cbor_encoder_create_map(enc, &map, len);

    cose_hdr_add_to_map(sign->hdrs.prot.c, &map);
    if (_is_sign1(sign)) {
        if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
            cose_key_protected_to_map(sign->signatures->signer, &map);
        }
        cose_hdr_add_to_map(sign->signatures->hdrs.prot.c, &map);
    }
    cbor_encoder_close_container(enc, &map);
    return CborNoError;
}

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen)
{
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buflen, 0);
    _cbor_protected(sign, &enc);
    if (!buflen) {
        return cbor_encoder_get_extra_bytes_needed(&enc);
    }
    return cbor_encoder_get_buffer_size(&enc, buf);
}

static void _place_cbor_protected(cose_sign_t *sign, CborEncoder *arr)
{
    if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
        size_t slen = _serialize_cbor_protected(sign, NULL, 0);
        cbor_encode_byte_string(arr, arr->data.ptr, slen);
        _serialize_cbor_protected(sign, arr->data.ptr - slen, slen);
    }
    else {
        cbor_encode_byte_string(arr, sign->hdrs.prot.b, sign->hdrs.prot_len);
    }
}

static int _add_signatures(cose_sign_t *sign, CborEncoder *arr)
{
    for (cose_signature_t *sig = sign->signatures; sig; sig = sig->next) {
        if (sig->signature_len) {
            CborEncoder enc_sig;
            /* Construct the array */
            cbor_encoder_create_array(arr, &enc_sig, 3);

            size_t slen = cose_signature_serialize_protected(sig, true, NULL, 0);
            cbor_encode_byte_string(&enc_sig, enc_sig.data.ptr, slen);
            cose_signature_serialize_protected(sig, true, enc_sig.data.ptr - slen, slen);
            /* Add unprotected headers to the signature struct */
            cose_signature_unprot_cbor(sig, &enc_sig);
            /* Add signature space */
            cbor_encode_byte_string(&enc_sig, sig->signature, sig->signature_len);
            cbor_encoder_close_container(arr, &enc_sig);
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

ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t len, uint8_t **out)
{
    /* The buffer here is used to contain dummy data a number of times */
    CborEncoder enc, arr;

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

    cbor_encoder_init(&enc, buf, len, 0);
    /* Build tag */
    if (!(cose_flag_isset(sign->flags, COSE_FLAGS_UNTAGGED))) {
        cbor_encode_tag(&enc,
            _is_sign1(sign) ? COSE_SIGN1 : COSE_SIGN);
    }
    /* Create the main array */
    cbor_encoder_create_array(&enc, &arr, 4);

    /* Create protected body header bstr */
    _place_cbor_protected(sign, &arr);

    /* Create unprotected body header map */
    _cbor_unprotected(sign, &arr);

    /* Create payload */
    if (cose_flag_isset(sign->flags, COSE_FLAGS_EXTDATA)) {
        cbor_encode_byte_string(&arr, NULL, 0);
    }
    else {
        cbor_encode_byte_string(&arr, sign->payload, sign->payload_len);
    }

    /* Now use the signatures to add to the signature array, still nonsense in the protected headers */
    if (_is_sign1(sign)) {
        cbor_encode_byte_string(&arr, sign->signatures->signature, sign->signatures->signature_len);
    }
    else {
        /* Create the signature array */
        CborEncoder sigs;
        cbor_encoder_create_array(&arr, &sigs, cose_signature_num(sign->signatures));
        _add_signatures(sign, &sigs);
        cbor_encoder_close_container(&arr, &sigs);
    }

    cbor_encoder_close_container(&enc, &arr);

    *out = buf;
    size_t res;
    if (cbor_encoder_get_extra_bytes_needed(&enc)) {
        res = COSE_ERR_NOMEM;
    }
    else {
        res = cbor_encoder_get_buffer_size(&enc, buf);
    }
    return res;
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len)
{
    CborParser p;
    CborValue it, arr;
    size_t alen = 0;
    CborError err = cbor_parser_init(buf, len, COSE_CBOR_VALIDATION, &p, &it);
    if (err) {
        return err;
    }
    sign->flags |= COSE_FLAGS_DECODE;

    /* Check tag values */
    if (cbor_value_is_tag(&it)) {
        cbor_value_advance(&it);
    }
    if (!cbor_value_is_array(&it))
    {
        return COSE_ERR_INVALID_CBOR;
    }
    cbor_value_get_array_length(&it, &alen);
    if (alen != 4) {
        return COSE_ERR_INVALID_CBOR;
    }

    cbor_value_enter_container(&it, &arr);
    if (!cbor_value_is_byte_string(&arr)) {
        return COSE_ERR_INVALID_CBOR;
    }

    cose_cbor_get_string(&arr, &sign->hdrs.prot.b, &sign->hdrs.prot_len);

    cbor_value_advance(&arr);
    if (!cbor_value_is_map(&arr)) {
        return COSE_ERR_INVALID_CBOR;
    }
    sign->hdrs.unprot.b = arr.ptr;

    /* Payload */
    cbor_value_advance(&arr);
    sign->hdrs.unprot_len = arr.ptr - sign->hdrs.unprot.b;
    if (!cbor_value_is_byte_string(&arr)) {
        return COSE_ERR_INVALID_CBOR;
    }

    cose_cbor_get_string(&arr, (const uint8_t **)&sign->payload, &sign->payload_len);
    if (!sign->payload_len) {
        /* Zero payload length, thus external payload */
        sign->flags |= COSE_FLAGS_EXTDATA;
        sign->payload = NULL;
    }

    cbor_value_advance(&arr);
    sign->sig = arr.ptr;
    if (cbor_value_is_byte_string(&arr)) {
        sign->flags |= COSE_FLAGS_SIGN1;
    }
    cbor_value_advance(&arr);
    sign->sig_len = arr.ptr - sign->sig;

    return COSE_OK;
}

void cose_sign_iter_init(cose_sign_t *sign, cose_sign_iter_t *iter)
{
    iter->sign = sign;
    cbor_parser_init(sign->sig, sign->sig_len, 0, &iter->p, &iter->it);
    if (cbor_value_is_array(&iter->it)) {
        cbor_value_enter_container(&iter->it, &iter->arr);
    }
    else {
        iter->arr = iter->it;
    }
}

bool cose_sign_iter(cose_sign_iter_t *iter, cose_signature_t *signature)
{
    bool res = false;
    if (!cbor_value_at_end(&iter->arr)) {
        if (cbor_value_is_byte_string(&iter->it)) {
            signature->hdrs.prot.b = iter->sign->hdrs.prot.b;
            signature->hdrs.prot_len = iter->sign->hdrs.prot_len;
            signature->hdrs.unprot.b = iter->sign->hdrs.unprot.b;
            signature->hdrs.unprot_len = iter->sign->hdrs.unprot_len;
            cose_cbor_get_string(&iter->arr, &signature->signature,
                    &signature->signature_len);
            res = true;
        }
        if (cbor_value_is_array(&iter->it)) {
            cose_signature_decode(signature, &iter->arr);
            cbor_value_advance(&iter->arr);
            res = true;
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
    ssize_t sig_len = _sign_sig_encode(sign, signature,
                                       _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                       buf, len);
    if (sig_len < 0) {
        return sig_len;
    }
    if (cose_crypto_verify(key, signature->signature, signature->signature_len, buf, sig_len) < 0) {
        res = COSE_ERR_CRYPTO;
    }
    signature->signer = tmp;
    return res;
}
