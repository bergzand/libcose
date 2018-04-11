/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cn-cbor/cn-cbor.h"
#include "cose.h"
#include "cose/cbor.h"
#include "cose/crypto.h"
#include "cose/intern.h"
#include <stdint.h>
#include <string.h>

#define COSE_HDR_SIZE_MAX 32


static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen, cn_cbor_context *ct, cn_cbor_errback *errp);
static cn_cbor *_sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, cn_cbor_context *ct, cn_cbor_errback *errp);
static ssize_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buf_size, cn_cbor_context *ct);
static cn_cbor *_cbor_unprotected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp);
static size_t _sig_serialize_protected(const cose_signature_t *sig, uint8_t *buf, size_t buflen, cn_cbor_context *ct, cn_cbor_errback *errp);

static cn_cbor *_sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_arr = cn_cbor_array_create(ct, errp);

    if (!cn_arr) {
        return NULL;
    }
    /* Add type string */
    cn_cbor *cn_sign_str = cn_cbor_string_create(type, ct, errp);
    CBOR_CATCH_ERR(cn_sign_str, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_sign_str, errp);

    /* Add body protected headers */
    cn_cbor *cn_body_prot = cn_cbor_data_create(sign->hdr_prot_ser, sign->hdr_prot_ser_len, ct, errp);
    CBOR_CATCH_ERR(cn_body_prot, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_body_prot, errp);

    /* Add signer protected headers */
    if (sig->hdr_protected_len) {
        cn_cbor *cn_signer_prot = cn_cbor_data_create(sig->hdr_protected, sig->hdr_protected_len, ct, errp);
        CBOR_CATCH_ERR(cn_signer_prot, cn_arr, ct);
        cn_cbor_array_append(cn_arr, cn_signer_prot, errp);
    }

    /* External aad */
    cn_cbor *cn_external = cn_cbor_data_create(sign->ext_aad, sign->ext_aad_len, ct, errp);
    CBOR_CATCH_ERR(cn_external, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_external, errp);

    /* Add payload */
    cn_cbor *cn_payload = cn_cbor_data_create(sign->payload, sign->payload_len, ct, errp);
    CBOR_CATCH_ERR(cn_payload, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_payload, errp);
    return cn_arr;
}

static ssize_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buf_size, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    cn_cbor *cn_arr = _sign_sig_cbor(sign, sig, type, ct, &errp);

    if (!cn_arr) {
        return cose_intern_err_translate(&errp);
    }
    size_t len = cn_cbor_encoder_write(buf, 0, buf_size, cn_arr);
    cn_cbor_free(cn_arr, ct);
    return (ssize_t)len;
}

static bool _sig_unprot_to_map(cose_signature_t *sig, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    if (cose_key_unprotected_to_map(sig->signer, map, ct, errp) < 0) {
        return false;
    }
    if (!cose_hdr_add_to_map(sig->hdrs, COSE_SIG_HDR_MAX, map, false, ct, errp)) {
        return false;
    }
    return true;
}

static bool _sig_prot_to_map(const cose_signature_t *sig, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    if (cose_key_protected_to_map(sig->signer, map, ct, errp) < 0) {
        return false;
    }
    if (!cose_hdr_add_to_map(sig->hdrs, COSE_SIG_HDR_MAX, map, true, ct, errp)) {
        return false;
    }
    return true;
}

static cn_cbor* _sig_unprot_cbor(cose_signature_t *sig, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *map = cn_cbor_map_create(ct, errp);

    if (!_sig_unprot_to_map(sig, map, ct, errp)) {
        cn_cbor_free(map, ct);
        return NULL;
    }
    return map;
}

static size_t _sig_serialize_protected(const cose_signature_t *sig, uint8_t *buf, size_t buflen,
                                        cn_cbor_context *ct, cn_cbor_errback *errp)
{
    size_t res = 0;
    cn_cbor *cn_prot = cn_cbor_map_create(ct, errp);
    if (!cn_prot) {
        return 0;
    }
    if (!_sig_prot_to_map(sig, cn_prot, ct, errp)) {
        cn_cbor_free(cn_prot, ct);
        return 0;
    }
    res = cn_cbor_encoder_write(buf, 0, buflen, cn_prot);
    cn_cbor_free(cn_prot, ct);

    return res;
}

static cn_cbor *_cbor_unprotected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *map = cn_cbor_map_create(ct, errp);

    if (!cose_hdr_add_to_map(sign->hdrs, COSE_SIGN_HDR_MAX, map, false, ct, errp)) {
        return NULL;
    }
    if (_is_sign1(sign)) {
        if (!_sig_unprot_to_map(sign->sigs, map, ct, errp)) {
            cn_cbor_free(map, ct);
            return NULL;
        }
    }
    return map;
}

static cn_cbor *_cbor_protected(cose_sign_t *sign,
                                cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *map = cn_cbor_map_create(ct, errp);
    if (!cose_hdr_add_to_map(sign->hdrs, COSE_SIGN_HDR_MAX, map, true, ct, errp)) {
        return NULL;
    }
    if (_is_sign1(sign)) {
        if (cose_key_protected_to_map(sign->sigs[0].signer, map, ct, errp) < 0) {
            cn_cbor_free(map, ct);
            return NULL;
        }
        if (!cose_hdr_add_to_map(sign->sigs[0].hdrs, COSE_SIG_HDR_MAX, map, true, ct, errp)) {
            cn_cbor_free(map, ct);
            return NULL;
        }
    }
    return map;
}

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen,
                                        cn_cbor_context *ct, cn_cbor_errback *errp)
{
    size_t res = 0;
    cn_cbor *cn_prot = _cbor_protected(sign, ct, errp);

    if (cn_prot) {
        res = cn_cbor_encoder_write(buf, 0, buflen, cn_prot);
        cn_cbor_free(cn_prot, ct);
    }

    return res;
}

static int _add_signatures(cose_sign_t *sign, cn_cbor *cn_sigs, cn_cbor_context *ct)
{
    cn_cbor_errback errp;

    for (int i = 0; i < sign->num_sigs; i++) {
        cose_signature_t *sig = &(sign->sigs[i]);
        if (sig->signature_len) {
            /* Construct the array */
            cn_cbor *sig_strct = cn_cbor_array_create(ct, &errp);

            cn_cbor *cn_sig_prot = cn_cbor_data_create(sig->hdr_protected, sig->hdr_protected_len, ct, &errp);
            CBOR_CATCH_RET_ERR(cn_sig_prot, sig_strct, ct, &errp);

            cn_cbor_array_append(sig_strct, cn_sig_prot, &errp);
            /* Add unprotected headers to the signature struct */
            cn_cbor *cn_sig_unprot = _sig_unprot_cbor(sig, ct, &errp);
            CBOR_CATCH_RET_ERR(cn_sig_unprot, sig_strct, ct, &errp);

            cn_cbor_array_append(sig_strct, cn_sig_unprot, &errp);
            /* Add signature space */
            cn_cbor *cn_sig = cn_cbor_data_create(sig->signature, sig->signature_len, ct, &errp);
            CBOR_CATCH_RET_ERR(cn_sig, sig_strct, ct, &errp);

            cn_cbor_array_append(sig_strct, cn_sig, &errp);

            cn_cbor_array_append(cn_sigs, sig_strct, &errp);
        }
    }
    return COSE_OK;
}

void cose_sign_init(cose_sign_t *sign, uint16_t flags)
{
    memset(sign, 0, sizeof(cose_sign_t));
    sign->flags = flags;
}

void cose_sign_set_payload(cose_sign_t *sign, void *payload, size_t len)
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

int cose_sign_generate_signature(cose_sign_t *sign, cose_signature_t *sig, uint8_t *buf, size_t len, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    uint8_t *buf_cbor = buf + cose_crypto_sig_size(sig->signer);
    size_t cbor_space = len - cose_crypto_sig_size(sig->signer);

    if (!sig->signer) {
        return COSE_ERR_NOINIT;
    }
    /* Build the data at an offset of the signature size */
    ssize_t sig_struct_len = _sign_sig_encode(sign, sig,
                                              _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                              buf_cbor, cbor_space, ct);
    if (sig_struct_len < 0) {
        return sig_struct_len;
    }
    cn_cbor *cn_arr = cn_cbor_decode(buf_cbor, (size_t)sig_struct_len, ct, &errp);
    if (!cn_arr) {
        return cose_intern_err_translate(&errp);
    }
    cn_cbor *cn_prot = cn_cbor_index(cn_arr, 1);

    if (!(_serialize_cbor_protected(sign,
                                    (uint8_t *)cn_prot->v.bytes, (size_t)cn_prot->length + 5,
                                    ct, &errp))) {
        cn_cbor_free(cn_arr, ct);
        return cose_intern_err_translate(&errp);
    }
    cn_prot = cn_cbor_index(cn_arr, 2);


    if (!(_is_sign1(sign))) {
        if (!(_sig_serialize_protected(sig, (uint8_t *)cn_prot->v.bytes,(size_t)cn_prot->length + 5, ct, &errp))) {
            cn_cbor_free(cn_arr, ct);
            return cose_intern_err_translate(&errp);
        }
    }
    cn_cbor_free(cn_arr, ct);
    int res = cose_crypto_sign(sig->signer, buf, &(sig->signature_len), buf_cbor, sig_struct_len);
    /* Store pointer to the signature */
    sig->signature = buf;
    return res;
}


/* TODO: splitme */
ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t len, uint8_t **out, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    /* The buffer here is used to contain dummy data a number of times */
    uint8_t *bufptr = buf;

    /* Determine if this requires sign or sign1 */
    if (sign->num_sigs == 1) {
        sign->flags |= COSE_FLAGS_SIGN1;
    }


    /* build cbor payload structure with signer array */
    /* Serialize protected so we know the length */
    {
        size_t prot_len = _serialize_cbor_protected(sign, buf, len, ct, &errp);
        if (!prot_len) {
            return cose_intern_err_translate(&errp);
        }
        sign->hdr_prot_ser_len = prot_len;
        sign->hdr_prot_ser = buf;
    }
    /* First generate all required signatures */
    for (int i = 0; i < sign->num_sigs; i++) {
        size_t sig_prot_len = 0;
        cose_signature_t *sig = &(sign->sigs[i]);
        /* Get to know the protected header length
         * Don't set if when using sign1, it is added to the body headers */
        if (!_is_sign1(sign)) {
            sig_prot_len = _sig_serialize_protected(sig, buf, len, ct, &errp);
            if (!sig_prot_len) {
                return cose_intern_err_translate(&errp);
            }
        }
        sig->hdr_protected_len = sig_prot_len;
        sig->hdr_protected = buf;

        /* Start generating the signature */
        int res = cose_sign_generate_signature(sign, sig, buf, len, ct);
        if (res != COSE_OK) {
            return res;
        }
        buf += sig->signature_len;
        len -= sig->signature_len;
    }
    /* Create the main array */
    cn_cbor *cn_arr = cn_cbor_array_create(ct, &errp);
    if (!cn_arr) {
        return cose_intern_err_translate(&errp);
    }

    /* Create protected body header bstr */
    cn_cbor *cn_prot = cn_cbor_data_create(bufptr, sign->hdr_prot_ser_len, ct, &errp);
    CBOR_CATCH_RET_ERR(cn_prot, cn_arr, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_prot, &errp);

    /* Create unprotected body header map */
    cn_cbor *cn_unprot = _cbor_unprotected(sign, ct, &errp);
    CBOR_CATCH_RET_ERR(cn_unprot, cn_arr, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_unprot, &errp);
    /* Create payload */
    if (cose_flag_isset(sign->flags, COSE_FLAGS_EXTDATA)) {
        cn_cbor *cn_payload = cn_cbor_data_create(NULL, 0, ct, &errp);
        CBOR_CATCH_RET_ERR(cn_payload, cn_arr, ct, &errp);
        cn_cbor_array_append(cn_arr, cn_payload, &errp);
    }
    else {
        cn_cbor *cn_payload = cn_cbor_data_create(sign->payload, sign->payload_len, ct, &errp);
        CBOR_CATCH_RET_ERR(cn_payload, cn_arr, ct, &errp);
        cn_cbor_array_append(cn_arr, cn_payload, &errp);
    }

    /* cn_arr contains the framework for our COSE sign struct.
     * The cn_prot would contain nonsense when serialized now, but we don't
     * care about that as it is replaced with actual data later */

    /* Now use the signatures to add to the signature array, still nonsense in the protected headers */
    if (_is_sign1(sign)) {
        cn_cbor *cn_sig = cn_cbor_data_create(sign->sigs[0].signature, sign->sigs[0].signature_len, ct, &errp);
        CBOR_CATCH_RET_ERR(cn_sig, cn_arr, ct, &errp);
        cn_cbor_array_append(cn_arr, cn_sig, &errp);
    }
    else {
        /* Create the signature array */
        cn_cbor *cn_sigs = cn_cbor_array_create(ct, &errp);
        CBOR_CATCH_RET_ERR(cn_sigs, cn_arr, ct, &errp);
        cn_cbor_array_append(cn_arr, cn_sigs, &errp);
        int sig_res = _add_signatures(sign, cn_sigs, ct);
        if (sig_res < 0) {
            cn_cbor_free(cn_arr, ct);
            return sig_res;
        }
    }

    cn_cbor *cn_top = cn_arr;
    if (!(cose_flag_isset(sign->flags, COSE_FLAGS_UNTAGGED))) {
        cn_top = cn_cbor_tag_create(
            _is_sign1(sign) ? COSE_SIGN1 : COSE_SIGN,
            cn_arr,
            ct,
            &errp);
        CBOR_CATCH_RET_ERR(cn_top, cn_arr, ct, &errp);
    }

    /* Serialize array */
    *out = buf;
    size_t res = cn_cbor_encoder_write(buf, 0, len, cn_top);
    cn_cbor_free(cn_top, ct);

    /* Deserialize again to fill protected headers */
    cn_top = cn_arr = cn_cbor_decode(buf, res, ct, &errp);
    if (!cn_top) {
        return cose_intern_err_translate(&errp);
    }

    if (cn_arr->type == CN_CBOR_TAG) {
        cn_arr = cn_arr->first_child;
    }
    /* add body protected header */
    cn_prot = cn_cbor_index(cn_arr, 0);
    if (!(_serialize_cbor_protected(sign, (uint8_t *)cn_prot->v.bytes, (size_t)cn_prot->length + 5, ct, &errp))) {
        cn_cbor_free(cn_top, ct);
        return cose_intern_err_translate(&errp);
    }

    if (!(_is_sign1(sign))) {
        cn_cbor *cn_sigs = cn_cbor_index(cn_arr, 3);
        /* Add signature protected headers */
        for (int i = 0; i < sign->num_sigs; i++) {
            const cose_signature_t *sig = &sign->sigs[i];
            cn_cbor *cn_sig_prot = cn_cbor_index(cn_cbor_index(cn_sigs, i), 0);
            if (!(_sig_serialize_protected(sig, (uint8_t *)cn_sig_prot->v.bytes, (size_t)cn_sig_prot->length + 5, ct, &errp))) {
                cn_cbor_free(cn_top, ct);
                return cose_intern_err_translate(&errp);
            }
        }
    }
    cn_cbor_free(cn_top, ct);

    return res;
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    cn_cbor *cn_in = cn_cbor_decode(buf, len, ct, &errp);
    cn_cbor *cn_start = cn_in;

    if (!(cn_in)) {
        return cose_intern_err_translate(&errp);
    }

    if (cn_in->type == CN_CBOR_TAG && (cn_in->v.uint == COSE_SIGN || cn_in->v.uint == COSE_SIGN1)) {
        cn_start = cn_in->first_child;
    }
    if (cn_start->type != CN_CBOR_ARRAY || cn_start->length != 4) {
        return -2;
    }
    cn_cbor *cn_hdr_prot = cn_cbor_index(cn_start, 0);
    cn_cbor *cn_hdr_unprot = cn_cbor_index(cn_start, 1);
    cn_cbor *cn_payload = cn_cbor_index(cn_start, 2);
    cn_cbor *cn_sigs = cn_cbor_index(cn_start, 3);

    sign->hdr_prot_ser = cn_hdr_prot->v.bytes;
    sign->hdr_prot_ser_len = cn_hdr_prot->length;
    sign->payload_len = cn_payload->length;
    if (!sign->payload_len) {
        /* Zero payload length, thus external payload */
        sign->flags |= COSE_FLAGS_EXTDATA;
        sign->payload = NULL;
    }
    else {
        sign->payload = cn_payload->v.bytes;
    }
    /* Fill protected headers */
    cose_hdr_add_prot_from_cbor(sign->hdrs, COSE_SIGN_HDR_MAX, cn_hdr_prot->v.bytes, cn_hdr_prot->length, ct, &errp);
    /* Fill unprotected headers */
    cose_hdr_add_unprot_from_cbor(sign->hdrs, COSE_SIGN_HDR_MAX, cn_hdr_unprot, ct, &errp);

    if (cn_sigs->type == CN_CBOR_ARRAY) {
        cn_cbor *cp;
        unsigned int i = 0;
        for (cp = cn_sigs->first_child; cp; cp = cp->next) {
            if (cp->type != CN_CBOR_ARRAY) {
                continue;
            }
            if (i >= COSE_SIGNATURES_MAX) {
                break;
            }
            cose_signature_t *psig = &(sign->sigs[i]);
            cn_cbor *prot = cn_cbor_index(cp, 0);
            psig->hdr_protected = prot->v.bytes;
            psig->hdr_protected_len = prot->length;
            /* TODO: copy array */
            cn_cbor *sig = cn_cbor_index(cp, 2);
            psig->signature = sig->v.bytes;
            psig->signature_len = sig->length;
            cose_hdr_add_prot_from_cbor(psig->hdrs, COSE_SIG_HDR_MAX, prot->v.bytes, prot->length, ct, &errp);
            cose_hdr_add_from_cbor(psig->hdrs, COSE_SIG_HDR_MAX, cn_cbor_index(cp, 1), 0, ct, &errp);
            i++;
        }
        sign->num_sigs = i;
        /* Probably a SIGN1 struct then */
    }
    else if (cn_sigs->type == CN_CBOR_BYTES) {
        sign->flags |= COSE_FLAGS_SIGN1;
        cose_signature_t *psig = &(sign->sigs[0]);
        psig->hdr_protected = NULL;
        psig->hdr_protected_len = 0;
        psig->signature = cn_sigs->v.bytes;
        psig->signature_len = cn_sigs->length;
        sign->num_sigs = 1;
    }
    else {
        cn_cbor_free(cn_in, ct);
        return COSE_ERR_INVALID_CBOR;
    }
    cn_cbor_free(cn_in, ct);

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
int cose_sign_verify(cose_sign_t *sign, cose_key_t *key, uint8_t idx, uint8_t *buf, size_t len, cn_cbor_context *ct)
{
    int res = COSE_OK;

    if (idx >= COSE_SIGNATURES_MAX) {
        return COSE_ERR_NOMEM;
    }
    cose_signature_t *sig = &sign->sigs[idx];
    ssize_t sig_len = _sign_sig_encode(sign, sig,
                                       _is_sign1(sign) ? SIG_TYPE_SIGNATURE1 : SIG_TYPE_SIGNATURE,
                                       buf, len, ct);
    if (sig_len < 0) {
        return sig_len;
    }
    if (cose_crypto_verify(key, sig->signature, sig->signature_len, buf, sig_len) < 0) {
        res = COSE_ERR_CRYPTO;
    }
    return res;
}
