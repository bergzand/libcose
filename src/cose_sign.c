/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <cbor.h>
#include "cose/conf.h"
#include "cose_defines.h"
#include "cose/cbor.h"
#include "cose/crypto.h"
#include "cose/hdr.h"
#include "cose/intern.h"
#include "cose/key.h"
#include "cose/sign.h"
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen);
static CborError _sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, CborEncoder *enc);
static ssize_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buf_size);
static CborError _cbor_unprotected(cose_sign_t *sign, CborEncoder *enc);
static size_t _sig_serialize_protected(const cose_sign_t *sign, const cose_signature_t *sig, uint8_t *buf, size_t buflen);

static CborError _sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, CborEncoder *enc)
{
    CborEncoder arr;
    size_t len = _is_sign1(sign) ? 4 : 5;
    cbor_encoder_create_array(enc, &arr, len);

    /* Add type string */
    cbor_encode_text_stringz(&arr, type);

    /* Add body protected headers */
    size_t slen = _serialize_cbor_protected(sign, NULL, 0);
    cbor_encode_byte_string(&arr, arr.data.ptr, slen);
    _serialize_cbor_protected(sign, arr.data.ptr - slen, slen);

    /* Add signer protected headers */
    if (!_is_sign1(sign)) {
        slen = _sig_serialize_protected(sign, sig, NULL, 0);
        cbor_encode_byte_string(&arr, arr.data.ptr, slen);
        _sig_serialize_protected(sign, sig, arr.data.ptr - slen, slen);
    }

    /* External aad */
    cbor_encode_byte_string(&arr, sign->ext_aad, sign->ext_aad_len);

    /* Add payload */
    cbor_encode_byte_string(&arr, sign->payload, sign->payload_len);
    cbor_encoder_close_container(enc, &arr);
    return CborNoError;
}

static ssize_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buflen)
{
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buflen, 0);
    _sign_sig_cbor(sign, sig, type, &enc);
    if (buflen) {
        return (ssize_t)cbor_encoder_get_buffer_size(&enc, buf);
    }
    else {
        return (ssize_t)cbor_encoder_get_extra_bytes_needed(&enc);
    }
}

static bool _sig_unprot_to_map(cose_signature_t *sig, CborEncoder *map)
{
    if (cose_key_unprotected_to_map(sig->signer, map) < 0) {
        return false;
    }
    if (!cose_hdr_add_to_map(sig->hdrs, COSE_SIG_HDR_MAX, map, false)) {
        return false;
    }
    return true;
}

static bool _sig_prot_to_map(const cose_sign_t *sign, const cose_signature_t *sig, CborEncoder *map)
{
    if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
        if (cose_key_protected_to_map(sig->signer, map) < 0) {
            return false;
        }
    }
    if (!cose_hdr_add_to_map(sig->hdrs, COSE_SIG_HDR_MAX, map, true)) {
        return false;
    }
    return true;
}

static CborError _sig_unprot_cbor(cose_signature_t *sig, CborEncoder *enc)
{
    CborEncoder map;
    /* Increment to also contain KID */
    size_t len = cose_hdr_size(sig->hdrs, COSE_SIG_HDR_MAX, false) + 1;
    cbor_encoder_create_map(enc, &map, len);
    CborError res = _sig_unprot_to_map(sig, &map);
    cbor_encoder_close_container(enc, &map);
    return res;
}

static size_t _sig_serialize_protected(const cose_sign_t *sign, const cose_signature_t *sig, uint8_t *buf, size_t buflen)
{
    CborEncoder enc, map;
    /* Also contains algo */
    size_t len = cose_hdr_size(sig->hdrs, COSE_SIG_HDR_MAX, true);
    len += cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE) ? 1 : 0;
    cbor_encoder_init(&enc, buf, buflen, 0);
    cbor_encoder_create_map(&enc, &map, len);
    _sig_prot_to_map(sign, sig, &map);
    cbor_encoder_close_container(&enc, &map);
    if (buflen) {
        return (ssize_t)cbor_encoder_get_buffer_size(&enc, buf);
    }
    else {
        return (ssize_t)cbor_encoder_get_extra_bytes_needed(&enc);
    }
}

static CborError _cbor_unprotected(cose_sign_t *sign, CborEncoder *enc)
{
    CborEncoder map;
    size_t len = cose_hdr_size(sign->hdrs, COSE_SIGN_HDR_MAX, false);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->sigs->hdrs, COSE_SIG_HDR_MAX, false) + 1;
    }
    cbor_encoder_create_map(enc, &map, len);
    cose_hdr_add_to_map(sign->hdrs, COSE_SIGN_HDR_MAX, &map, false);
    if (_is_sign1(sign)) {
        _sig_unprot_to_map(sign->sigs, &map);
    }
    cbor_encoder_close_container(enc, &map);
    return 0;
}

static CborError _cbor_protected(cose_sign_t *sign, CborEncoder *enc)
{
    CborEncoder map;
    size_t len = cose_hdr_size(sign->hdrs, COSE_SIGN_HDR_MAX, true);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->sigs->hdrs, COSE_SIG_HDR_MAX, true);
        len += cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE) ? 1 : 0;
    }
    cbor_encoder_create_map(enc, &map, len);

    cose_hdr_add_to_map(sign->hdrs, COSE_SIGN_HDR_MAX, &map, true);
    if (_is_sign1(sign)) {
        if (cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE)) {
            cose_key_protected_to_map(sign->sigs[0].signer, &map);
        }
        cose_hdr_add_to_map(sign->sigs[0].hdrs, COSE_SIG_HDR_MAX, &map, true);
    }
    cbor_encoder_close_container(enc, &map);
    return CborNoError;
}

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen)
{
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buflen, 0);
    _cbor_protected(sign, &enc);
    if (buflen) {
        return (size_t)cbor_encoder_get_buffer_size(&enc, buf);
    }
    else {
        return (size_t)cbor_encoder_get_extra_bytes_needed(&enc);
    }
}

static int _add_signatures(cose_sign_t *sign, CborEncoder *arr)
{
    for (int i = 0; i < sign->num_sigs; i++) {
        cose_signature_t *sig = &(sign->sigs[i]);
        if (sig->signature_len) {
            CborEncoder enc_sig;
            /* Construct the array */
            cbor_encoder_create_array(arr, &enc_sig, 3);

            size_t slen = _sig_serialize_protected(sign, sig, NULL, 0);
            cbor_encode_byte_string(&enc_sig, enc_sig.data.ptr, slen);
            _sig_serialize_protected(sign, sig, enc_sig.data.ptr - slen, slen);
            /* Add unprotected headers to the signature struct */
            _sig_unprot_cbor(sig, &enc_sig);
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

int cose_sign_add_signer(cose_sign_t *sign, const cose_key_t *key)
{
    /* TODO: define status codes */
    if (sign->num_sigs == COSE_SIGNATURES_MAX) {
        return COSE_ERR_NOMEM;
    }
    /* Convenience pointer */
    cose_signature_t *sig = &(sign->sigs[sign->num_sigs]);
    sig->signer = key;

    return sign->num_sigs++;
}

int cose_sign_generate_signature(cose_sign_t *sign, cose_signature_t *sig, uint8_t *buf, size_t len)
{
    uint8_t *buf_cbor = buf + cose_crypto_sig_size(sig->signer);
    size_t cbor_space = len - cose_crypto_sig_size(sig->signer);

    if (!sig->signer) {
        return COSE_ERR_NOINIT;
    }
    /* Build the data at an offset of the signature size */
    ssize_t sig_struct_len = _sign_sig_encode(sign, sig,
                                              _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                              buf_cbor, cbor_space);
    if (sig_struct_len < 0) {
        return sig_struct_len;
    }
    int res = cose_crypto_sign(sig->signer, buf, &(sig->signature_len), buf_cbor, sig_struct_len);
    /* Store pointer to the signature */
    sig->signature = buf;
    return res;
}

ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t len, uint8_t **out)
{
    /* The buffer here is used to contain dummy data a number of times */
    uint8_t *bufptr = buf;
    CborEncoder enc, arr;

    sign->flags |= COSE_FLAGS_ENCODE;

    /* Determine if this requires sign or sign1 */
    if (sign->num_sigs == 1) {
        sign->flags |= COSE_FLAGS_SIGN1;
    }

    /* First generate all required signatures */
    for (int i = 0; i < sign->num_sigs; i++) {
        cose_signature_t *sig = &(sign->sigs[i]);
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
    size_t slen = _serialize_cbor_protected(sign, NULL, 0);
    cbor_encode_byte_string(&arr, bufptr, slen);
    _serialize_cbor_protected(sign, arr.data.ptr - slen, slen);

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
        cbor_encode_byte_string(&arr, sign->sigs[0].signature, sign->sigs[0].signature_len);
    }
    else {
        /* Create the signature array */
        CborEncoder sigs;
        cbor_encoder_create_array(&arr, &sigs, sign->num_sigs);
        _add_signatures(sign, &sigs);
        cbor_encoder_close_container(&arr, &sigs);
    }

    cbor_encoder_close_container(&enc, &arr);

    *out = buf;
    size_t res = cbor_encoder_get_buffer_size(&enc, buf);
    return res;
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len)
{
    CborParser p;
    CborValue it, arr;
    size_t alen = 0;
    CborError err = cbor_parser_init(buf, len, 0, &p, &it);
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

    cose_cbor_get_string(&arr, &sign->hdr_prot_ser, &sign->hdr_prot_ser_len);
    cose_hdr_add_prot_from_cbor(sign->hdrs, COSE_SIGN_HDR_MAX, sign->hdr_prot_ser, sign->hdr_prot_ser_len);

    cbor_value_advance(&arr);
    if (!cbor_value_is_map(&arr)) {
        return COSE_ERR_INVALID_CBOR;
    }
    cose_hdr_add_unprot_from_cbor(sign->hdrs, COSE_SIGN_HDR_MAX, &arr);

    /* Payload */
    cbor_value_advance(&arr);
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
    if (cbor_value_is_array(&arr)) {
        CborValue cp;
        cbor_value_enter_container(&arr, &cp);
        unsigned int i = 0;
        while (!cbor_value_at_end(&cp)) {
            CborValue sig;
            cose_signature_t *psig = &(sign->sigs[i]);
            if (!cbor_value_is_array(&cp)) {
                cbor_value_advance(&cp);
                continue;
            }
            if (i >= COSE_SIGNATURES_MAX) {
                break;
            }
            cbor_value_enter_container(&cp, &sig);
            /* Protected headers */
            cose_cbor_get_string(&sig, &psig->hdr_protected, &psig->hdr_protected_len);
            cose_hdr_add_prot_from_cbor(psig->hdrs, COSE_SIG_HDR_MAX, psig->hdr_protected, psig->hdr_protected_len);
            /* Unprotected headers */
            cbor_value_advance(&sig);
            cose_hdr_add_from_cbor(psig->hdrs, COSE_SIG_HDR_MAX, &sig, 0);
            /* Signature */
            cbor_value_advance(&sig);
            cose_cbor_get_string(&sig, &psig->signature, &psig->signature_len);
            cbor_value_advance(&sig);
            cbor_value_leave_container(&cp, &sig);
            i++;
        }
        sign->num_sigs = i;
    }
    /* Probably a SIGN1 struct then */
    else if (cbor_value_is_byte_string(&arr)) {
        sign->flags |= COSE_FLAGS_SIGN1;
        cose_signature_t *psig = &(sign->sigs[0]);
        psig->hdr_protected = NULL;
        psig->hdr_protected_len = 0;
        cose_cbor_get_string(&arr, &psig->signature, &psig->signature_len);
        sign->num_sigs = 1;
    }
    else {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

ssize_t cose_sign_get_kid(cose_sign_t *sign, uint8_t idx, const uint8_t **kid)
{
    *kid = NULL;
    if (idx >= COSE_SIGNATURES_MAX) {
        return COSE_ERR_INVALID_PARAM;
    }
    cose_hdr_t *hdr = cose_hdr_get(sign->sigs[idx].hdrs, COSE_SIG_HDR_MAX, COSE_HDR_KID);
    if (hdr) {
        *kid = hdr->v.data;
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

cose_hdr_t *cose_sign_get_header(cose_sign_t *sign, int32_t key)
{
    return cose_hdr_get(sign->hdrs, COSE_SIGN_HDR_MAX, key);
}

cose_hdr_t *cose_sign_get_protected(cose_sign_t *sign, int32_t key)
{
    return cose_hdr_get_bucket(sign->hdrs, COSE_SIGN_HDR_MAX,
                               key, true);
}

cose_hdr_t *cose_sign_get_unprotected(cose_sign_t *sign, int32_t key)
{
    return cose_hdr_get_bucket(sign->hdrs, COSE_SIGN_HDR_MAX, key, false);
}

cose_hdr_t *cose_sign_sig_get_header(cose_sign_t *sign, uint8_t idx, int32_t key)
{
    if (idx >= COSE_SIGNATURES_MAX) {
        return NULL;
    }
    if (_is_sign1(sign) && idx == 0) {
        return cose_hdr_get(sign->hdrs, COSE_SIG_HDR_MAX, key);
    }
    return cose_hdr_get(sign->sigs[idx].hdrs, COSE_SIG_HDR_MAX, key);
}

cose_hdr_t *cose_sign_sig_get_protected(cose_sign_t *sign, uint8_t idx, int32_t key)
{
    if (idx >= COSE_SIGNATURES_MAX) {
        return NULL;
    }
    if (_is_sign1(sign) && idx == 0) {
        return cose_hdr_get_bucket(sign->hdrs, COSE_SIG_HDR_MAX, key, true);
    }
    return cose_hdr_get_bucket(sign->sigs[idx].hdrs, COSE_SIG_HDR_MAX,
                               key, true);
}

cose_hdr_t *cose_sign_sig_get_unprotected(cose_sign_t *sign, uint8_t idx, int32_t key)
{
    if (idx >= COSE_SIGNATURES_MAX) {
        return NULL;
    }
    if (_is_sign1(sign) && idx == 0) {
        return cose_hdr_get_bucket(sign->hdrs, COSE_SIG_HDR_MAX, key, false);
    }
    return cose_hdr_get_bucket(sign->sigs[idx].hdrs, COSE_SIG_HDR_MAX, key, false);
}

/* Try to verify the structure with a signer and a signature idx */
int cose_sign_verify(cose_sign_t *sign, cose_key_t *key, uint8_t idx, uint8_t *buf, size_t len)
{
    int res = COSE_OK;

    if (idx >= COSE_SIGNATURES_MAX) {
        return COSE_ERR_NOMEM;
    }
    cose_signature_t *sig = &sign->sigs[idx];
    const cose_key_t *tmp = sig->signer;
    sig->signer = key;
    ssize_t sig_len = _sign_sig_encode(sign, sig,
                                       _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                       buf, len);
    if (sig_len < 0) {
        return sig_len;
    }
    if (cose_crypto_verify(key, sig->signature, sig->signature_len, buf, sig_len) < 0) {
        res = COSE_ERR_CRYPTO;
    }
    sig->signer = tmp;
    return res;
}
