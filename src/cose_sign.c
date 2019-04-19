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

/**********************
 * encoding functions *
 **********************/
static size_t _serialize_cbor_protected(cose_sign_enc_t *sign, uint8_t *buf, size_t buflen);
static void _place_cbor_protected(cose_sign_enc_t *sign, nanocbor_encoder_t *arr);

/**
 * Internal function to check if the object is a sign1 structure
 *
 * @param   sign        Sign object to check
 *
 * @return              True if the object is a sign1 object
 */
static inline bool _is_sign1(const cose_sign_enc_t *sign)
{
    return (sign->flags & COSE_FLAGS_SIGN1);
}

static inline bool _is_sign1_dec(const cose_sign_dec_t *sign)
{
    return (sign->flags & COSE_FLAGS_SIGN1);
}

static int _enc_cbor_protected(cose_sign_enc_t *sign, nanocbor_encoder_t *enc)
{
    size_t len = cose_hdr_size(sign->hdrs.prot);
    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->signatures->hdrs.prot);
        len += cose_flag_isset(sign->flags, COSE_FLAGS_ENCODE) ? 1 : 0;
    }
    nanocbor_fmt_map(enc, len);

    cose_hdr_encode_to_map(sign->hdrs.prot, enc);
    if (_is_sign1(sign)) {
        cose_key_protected_to_map(sign->signatures->signer, enc);
        cose_hdr_encode_to_map(sign->signatures->hdrs.prot, enc);
    }
    return 0;
}

static size_t _serialize_cbor_protected(cose_sign_enc_t *sign, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buflen);
    _enc_cbor_protected(sign, &enc);
    return nanocbor_encoded_len(&enc);
}

static void _place_cbor_protected(cose_sign_enc_t *sign, nanocbor_encoder_t *arr)
{
    size_t slen = _serialize_cbor_protected(sign, NULL, 0);
    nanocbor_put_bstr(arr, arr->cur, slen);
    _serialize_cbor_protected(sign, arr->cur - slen, slen);
}

static void _sign_sig_cbor_start(nanocbor_encoder_t *enc, bool sign1)
{
    size_t len = sign1 ? COSE_SIGN_SIG_SIGN1_LEN
                       : COSE_SIGN_SIG_SIGN_LEN;
    nanocbor_fmt_array(enc, len);

    /* Add type string */
    const char * type = sign1 ? SIG_TYPE_SIGNATURE1
                              : SIG_TYPE_SIGNATURE;
    nanocbor_put_tstr(enc, type);
}

static void _sign_sig_cbor(cose_sign_enc_t *sign, cose_signature_t *sig, nanocbor_encoder_t *enc)
{
    _sign_sig_cbor_start(enc, _is_sign1(sign));

    /* Add body protected headers */
    _place_cbor_protected(sign, enc);

    /* Add signer protected headers */
    if (!_is_sign1(sign)) {
        size_t slen = cose_signature_serialize_protected(sig, true, NULL, 0);
        nanocbor_put_bstr(enc, enc->cur, slen);
        cose_signature_serialize_protected(sig, true, enc->cur - slen, slen);
    }

    /* External aad */
    nanocbor_put_bstr(enc, sign->ext_aad, sign->ext_aad_len);

    /* Add payload */
    nanocbor_put_bstr(enc, sign->payload, sign->payload_len);
}

static size_t _enc_sign_sig(cose_sign_enc_t *sign, cose_signature_t *sig, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buflen);
    _sign_sig_cbor(sign, sig, &enc);
    return nanocbor_encoded_len(&enc);
}

static int _add_signatures(cose_sign_enc_t *sign, nanocbor_encoder_t *arr)
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

static int _sign_generate_signature(cose_sign_enc_t *sign, cose_signature_t *sig, uint8_t *buf, size_t len)
{
    uint8_t *buf_cbor = buf + cose_crypto_sig_size(sig->signer);
    size_t cbor_space = len - cose_crypto_sig_size(sig->signer);

    if (!sig->signer) {
        return COSE_ERR_NOINIT;
    }
    /* Build the data at an offset of the signature size */
    size_t sig_struct_len = _enc_sign_sig(sign, sig,
                                           buf_cbor, cbor_space);
    int res = cose_crypto_sign(sig->signer, buf, &(sig->signature_len), buf_cbor, sig_struct_len);
    /* Store pointer to the signature */
    sig->signature = buf;
    return res;
}

static int _enc_cbor_unprotected(cose_sign_enc_t *sign, nanocbor_encoder_t *enc)
{
    size_t len = cose_hdr_size(sign->hdrs.unprot);

    if (_is_sign1(sign)) {
        len += cose_hdr_size(sign->signatures->hdrs.unprot) + 1;
    }

    nanocbor_fmt_map(enc, len);
    cose_hdr_encode_to_map(sign->hdrs.unprot, enc);

    if (_is_sign1(sign)) {
        cose_signature_unprot_to_map(sign->signatures, enc);
    }
    return 0;
}

void cose_sign_init(cose_sign_enc_t *sign, uint16_t flags)
{
    memset(sign, 0, sizeof(cose_sign_enc_t));
    sign->flags = flags;
}

void cose_sign_set_payload(cose_sign_enc_t *sign, const void *payload, size_t len)
{
    sign->payload = payload;
    sign->payload_len = len;
}

void cose_sign_set_external_aad(cose_sign_enc_t *sign,
                                const void *ext, size_t len)
{
    sign->ext_aad = ext;
    sign->ext_aad_len = len;
}

void cose_sign_add_signer(cose_sign_enc_t *sign, cose_signature_t *signer, const cose_key_t *key)
{
    signer->next = sign->signatures;
    sign->signatures = signer;
    signer->signer = key;
}

COSE_ssize_t cose_sign_encode(cose_sign_enc_t *sign, uint8_t *buf, size_t len, uint8_t **out)
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
        int res = _sign_generate_signature(sign, sig, buf, len);
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
    _enc_cbor_unprotected(sign, &enc);

    /* Create payload */
    if (cose_flag_isset(sign->flags, COSE_FLAGS_EXTDATA)) {
        nanocbor_fmt_null(&enc);
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

/**********************
 * decoding functions *
 **********************/
static int _sign_decode_get_prot(const cose_sign_dec_t *sign, const uint8_t **buf, size_t *len)
{
    return cose_cbor_decode_get_prot(sign->buf, sign->len, buf, len);
}

#if 0
static int _sign_decode_get_unprot(const cose_sign_dec_t *sign, const uint8_t **buf, size_t *len)
{
    return cose_cbor_decode_get_unprot(sign->buf, sign->len, buf, len);
}
#endif

static int _sign_decode_get_sigs(const cose_sign_dec_t *sign, const uint8_t **buf, size_t *len)
{
    nanocbor_value_t arr;

    if (cose_cbor_decode_get_pos(sign->buf, sign->len, &arr, 3) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_subcbor(&arr, buf, len) < 0 ) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

static int _sign1_decode_sig(const cose_sign_dec_t *sign, const uint8_t **buf, size_t *len)
{
    nanocbor_value_t arr;
    if (cose_cbor_decode_get_pos(sign->buf, sign->len, &arr, 3) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_bstr(&arr, buf, len) < 0 ) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

static void _sign_sig_cbor_dec(const cose_sign_dec_t *sign, cose_signature_dec_t *sig, nanocbor_encoder_t *enc)
{
    _sign_sig_cbor_start(enc, _is_sign1_dec(sign));
    const uint8_t *buf;
    size_t len;

    /* Sign protected */
    _sign_decode_get_prot(sign, &buf, &len);
    nanocbor_put_bstr(enc, buf, len);

    if (!_is_sign1_dec(sign)) {
        const uint8_t *sig_prot_buf;
        size_t sig_prot_len = 0;
        cose_signature_decode_protected_buf(sig, &sig_prot_buf, &sig_prot_len);
        nanocbor_put_bstr(enc, sig_prot_buf, sig_prot_len);
    }

    nanocbor_put_bstr(enc, sign->ext_aad, sign->ext_aad_len);

    nanocbor_put_bstr(enc, sign->payload, sign->payload_len);
}

static size_t _dec_sign_sig(const cose_sign_dec_t *sign, cose_signature_dec_t *sig, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buflen);
    _sign_sig_cbor_dec(sign, sig, &enc);
    return nanocbor_encoded_len(&enc);
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_dec_t *sign, const uint8_t *buf, size_t len)
{
    nanocbor_value_t p;
    nanocbor_value_t arr;

    sign->ext_aad = NULL;
    sign->ext_aad_len = 0;
    sign->flags = 0;

    sign->buf = buf;
    sign->len = len;

    nanocbor_decoder_init(&p, buf, len);
    sign->flags |= COSE_FLAGS_DECODE;

    /* Check tag values */
    if (nanocbor_get_type(&p) == NANOCBOR_TYPE_TAG) {
        nanocbor_skip_simple(&p);
        nanocbor_value_t tmp = p;
        if (nanocbor_get_subcbor(&tmp, &sign->buf, &sign->len) < 0) {
            return COSE_ERR_INVALID_CBOR;
        }
    }
    else {
        sign->flags |= COSE_FLAGS_UNTAGGED;
    }

    if (nanocbor_enter_array(&p, &arr) < 0 ||
            nanocbor_container_remaining(&arr) != 4) {
        return COSE_ERR_INVALID_CBOR;
    }

    /* Prot headers and unprot headers */
    /* NOLINTNEXTLINE(misc-redundant-expression) */
    if (nanocbor_skip(&arr) < 0 || nanocbor_skip(&arr) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_null(&arr) >= 0) {
        /* Zero payload length, thus external payload */
        sign->flags |= COSE_FLAGS_EXTDATA;
        sign->payload = NULL;
        sign->payload_len = 0;
    }
    else if (nanocbor_get_bstr(&arr, (const uint8_t **)&sign->payload,
                               &sign->payload_len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_type(&arr) == NANOCBOR_TYPE_BSTR) {
        sign->flags |= COSE_FLAGS_SIGN1;
    }
    else if (nanocbor_get_type(&arr) != NANOCBOR_TYPE_ARR) {
        return COSE_ERR_INVALID_CBOR;
    }

    return COSE_OK;
}

void cose_sign_decode_payload(const cose_sign_dec_t *sign, const uint8_t **payload,
                              size_t *len)
{
    *payload = (const uint8_t*)sign->payload;
    *len = sign->payload_len;
}

bool cose_sign_signature_iter(const cose_sign_dec_t *sign,
                              cose_signature_dec_t *signature)
{
    if(_is_sign1_dec(sign) && !signature->buf) {
        cose_signature_decode_init(signature, sign->buf, sign->len);
        return true;
    }
    const uint8_t *buf = NULL;
    size_t len = 0;
    nanocbor_value_t tmp;
    nanocbor_value_t arr;

    _sign_decode_get_sigs(sign, &buf, &len);
    nanocbor_decoder_init(&tmp, buf, len);
    nanocbor_enter_array(&tmp, &arr);

    while ((signature->buf >= arr.cur) && !nanocbor_at_end(&arr)) {
        nanocbor_skip(&arr);
    }
    if (!nanocbor_at_end(&arr)) {
        const uint8_t *sig_buf;
        size_t sig_len = 0;
        if (nanocbor_get_subcbor(&arr, &sig_buf, &sig_len) < 0) {
            return false;
        }
        cose_signature_decode_init(signature, sig_buf, sig_len);
        return true;
    }
    return false;
}

int cose_sign_decode_header(const cose_sign_dec_t *sign, cose_hdr_t *hdr, int32_t key)
{
    int res = cose_sign_decode_protected(sign, hdr, key);
    if (res < 0) {
        res = cose_sign_decode_unprotected(sign, hdr, key);
    }
    return res;
}

int cose_sign_decode_protected(const cose_sign_dec_t *sign, cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *hdrs;
    size_t len;
    if (cose_cbor_decode_get_prot(sign->buf, sign->len, &hdrs, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(hdrs, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

int cose_sign_decode_unprotected(const cose_sign_dec_t *sign, cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *hdrs;
    size_t len;
    if (cose_cbor_decode_get_unprot(sign->buf, sign->len, &hdrs, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(hdrs, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

void cose_sign_decode_set_payload(cose_sign_dec_t *sign,
                                  const void *payload, size_t len)
{
    sign->payload = payload;
    sign->payload_len = len;
}

/* Try to verify the structure with a signer and a signature */
int cose_sign_verify(const cose_sign_dec_t *sign, cose_signature_dec_t *signature, cose_key_t *key, uint8_t *buf, size_t len)
{
    const uint8_t *signature_buf = NULL;
    size_t signature_len = 0;
    int res = COSE_OK;

    size_t sig_len = _dec_sign_sig(sign, signature, buf, len);

    if (_is_sign1_dec(sign)) {
        _sign1_decode_sig(sign, &signature_buf, &signature_len);
    }
    else {
         cose_signature_decode_signature(signature, &signature_buf, &signature_len);
    }

    if (cose_crypto_verify(key, signature_buf, signature_len, buf, sig_len) < 0) {
        res = COSE_ERR_CRYPTO;
    }
    return res;
}

int cose_sign_verify_first(const cose_sign_dec_t* sign, cose_key_t *key,
                           uint8_t *buf, size_t len)
{
    cose_signature_dec_t signature;
    cose_signature_decode_init(&signature, NULL, 0);
    if (!cose_sign_signature_iter(sign, &signature)) {
        return COSE_ERR_INVALID_CBOR;
    }
    return cose_sign_verify(sign, &signature, key, buf, len);
}

