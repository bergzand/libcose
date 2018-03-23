/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cn-cbor/cn-cbor.h"
#include "cose.h"
#include "cose/intern.h"
#include "cose/cbor.h"
#include "cose/crypto.h"
#include "cose/sign.h"

#define COSE_HDR_SIZE_MAX 32


static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen, cn_cbor_context *ct, cn_cbor_errback *errp);
static cn_cbor *_sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, cn_cbor_context *ct, cn_cbor_errback *errp);
static ssize_t _sign_sig_encode(cose_sign_t *sign, cose_signature_t *sig, const char *type, uint8_t *buf, size_t buf_size, cn_cbor_context *ct);
static cn_cbor *_cbor_unprotected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp);
static cn_cbor *_build_cbor_protected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp);
static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen, cn_cbor_context *ct, cn_cbor_errback *errp);

static cn_cbor *_sign_sig_cbor(cose_sign_t *sign, cose_signature_t *sig, const char *type, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_arr = cn_cbor_array_create(ct, errp);
    /* Add type string */
    cn_cbor *cn_sign_str = cn_cbor_string_create(type, ct, errp);
    CBOR_CATCH_ERR(cn_sign_str, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_sign_str, errp);

    /* Add body protected headers */
    cn_cbor *cn_body_prot = cn_cbor_data_create(sign->hdr_prot_ser, sign->hdr_prot_ser_len, ct, errp);
    CBOR_CATCH_ERR(cn_body_prot, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_body_prot, errp);

    /* Add signer protected headers */
    cn_cbor *cn_signer_prot = cn_cbor_data_create(sig->hdr_protected, sig->hdr_protected_len, ct, errp);
    CBOR_CATCH_ERR(cn_signer_prot, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_signer_prot, errp);

    /* Empty external aad */
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
    if (!(cn_arr)) {
        return cose_intern_err_translate(&errp);
    }
    size_t len = cn_cbor_encoder_write(buf, 0, buf_size, cn_arr);
    cn_cbor_free(cn_arr, ct);
    return (ssize_t)len;
}

static cn_cbor *_cbor_unprotected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    (void)sign;
    return cn_cbor_map_create(ct, errp);
}

static cn_cbor *_build_cbor_protected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* No support for protected content headers yet, returning an empty map */
    (void)sign;
    return cn_cbor_map_create(ct, errp);
}

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *prot = _build_cbor_protected(sign, ct, errp);
    size_t res = cn_cbor_encoder_write(buf, 0, buflen, prot);

    cn_cbor_free(prot, ct);
    return res;
}

//static size_t _cbor_prot(cose_sign_t *sign, cn_cbor *cn_prot, cn_cbor_context *ct)
//{
//    (void)sign;
//    (void)cn_prot;
//    (void)ct;
//    for (int i = 0; i < COSE_SIGN_HDR_PROTECTED_MAX; i++) {
//        if (sign->hdr_protected[i].id != 0) {
//            /** Implement things */
//        }
//    }
//    return 0;
//
//}

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

int cose_sign_add_signer(cose_sign_t *sign, const cose_signer_t *signer)
{
    /* TODO: define status codes */
    if (sign->num_sigs == COSE_SIGNATURES_MAX) {
        return COSE_ERR_NOMEM;
    }
    /* Convenience pointer */
    cose_signature_t *sig = &(sign->sigs[sign->num_sigs]);
    sig->signer = signer;

    /* Add unprotected headers to the signature struct */

    /* Serialize signer protected headers */
    sign->num_sigs++;
    return COSE_OK;
}

int cose_sign_generate_signature(cose_sign_t *sign, cose_signature_t *sig, uint8_t *buf, size_t bufsize, cn_cbor_context *ct)
{
    uint8_t *buf_cbor = buf + cose_crypto_sig_size_ed25519();
    size_t cbor_space = bufsize - cose_crypto_sig_size_ed25519();
    if (!(sig->signer)) {
        return COSE_ERR_NOINIT;
    }
    /* Build the data at an offset of the signature size */
    size_t sig_struct_len = _sign_sig_encode(sign, sig, SIG_TYPE_SIGNATURE, buf_cbor, cbor_space, ct);
    cn_cbor *cn_arr = cn_cbor_decode(buf_cbor, sig_struct_len, ct, NULL);
    cn_cbor *cn_prot = cn_cbor_index(cn_arr, 1);

    _serialize_cbor_protected(sign, (uint8_t *)cn_prot->v.bytes, cn_prot->length + 5, ct, NULL);
    cn_prot = cn_cbor_index(cn_arr, 2);
    cose_signer_serialize_protected(sig->signer, (uint8_t *)cn_prot->v.bytes, cn_prot->length + 5, ct, NULL);
    cn_cbor_free(cn_arr, ct);
    printf("Signing: \n");
    print_bytestr(buf_cbor, sig_struct_len);
    printf("\n");
    cose_crypto_sign_ed25519(buf, &(sig->signature_len), buf_cbor, sig_struct_len, sig->signer->d);
    /* Store pointer to the signature */
    sig->signature = buf;
    return COSE_OK;
}


/* TODO: splitme */
ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t bufsize, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* The buffer here is used to contain dummy data a number of times */
    uint8_t *bufptr = buf;

    /* build cbor payload structure with signer array */
    /* Serialize protected so we know the length */
    sign->hdr_prot_ser_len = _serialize_cbor_protected(sign, buf, bufsize, ct, errp);
    sign->hdr_prot_ser = buf;


    /* First generate all required signatures */
    for (int i = 0; i < sign->num_sigs; i++) {
        cose_signature_t *sig = &(sign->sigs[i]);
        /* Get to know the protected header length */
        sig->hdr_protected_len = cose_signer_serialize_protected(sig->signer, buf, bufsize, ct, errp);
        sig->hdr_protected = buf;
        /* Start generating the signature */
        cose_sign_generate_signature(sign, sig, buf, bufsize, ct);
        buf += sig->signature_len;
        bufsize -= sig->signature_len;
    }
    /* Create the main array */
    cn_cbor *cn_arr = cn_cbor_array_create(ct, errp);
    /* Create protected body header bstr */
    cn_cbor *cn_prot = cn_cbor_data_create(bufptr, sign->hdr_prot_ser_len, ct, errp);
    cn_cbor_array_append(cn_arr, cn_prot, errp);
    /* Create unprotected body header map */
    cn_cbor *cn_unprot = _cbor_unprotected(sign, ct, errp);
    cn_cbor_array_append(cn_arr, cn_unprot, errp);
    /* Create payload */
    cn_cbor *cn_payload = cn_cbor_data_create(sign->payload, sign->payload_len, ct, errp);
    cn_cbor_array_append(cn_arr, cn_payload, errp);
    /* Create the signature array */
    cn_cbor *cn_sigs = cn_cbor_array_create(ct, errp);
    cn_cbor_array_append(cn_arr, cn_sigs, errp);

    /* cn_arr contains the framework for our COSE sign struct.
     * The cn_prot would contain nonsense when serialized now, but we don't
     * care about that as it is replaced with actual data later */

    /* Now use the signatures to add to the signature array, still nonsense in the protected headers */
    for (int i = 0; i < sign->num_sigs; i++) {
        cose_signature_t *sig = &(sign->sigs[i]);
        if (sig->signature_len) {
            /* Construct the array */
            cn_cbor *sig_strct = cn_cbor_array_create(ct, errp);

            cn_cbor *cn_sig_prot = cn_cbor_data_create(sig->hdr_protected, sig->hdr_protected_len, ct, errp);
            cn_cbor_array_append(sig_strct, cn_sig_prot, errp);
            /* Add unprotected headers to the signature struct */
            cn_cbor *cn_sig_unprot = cose_signer_cbor_unprotected(sig->signer, ct, errp);
            cn_cbor_array_append(sig_strct, cn_sig_unprot, errp);
            cn_cbor *cn_sig = cn_cbor_data_create(sig->signature, sig->signature_len, ct, errp);
            cn_cbor_array_append(sig_strct, cn_sig, errp);

            cn_cbor_array_append(cn_sigs, sig_strct, errp);
        }
    }

    cn_cbor *cn_top = cn_arr;
    if (!(cose_flag_isset(sign->flags, COSE_FLAGS_UNTAGGED))) {
        cn_top = cn_cbor_tag_create(COSE_SIGN, cn_arr, ct, errp);
    }

    /* Serialize array */
    size_t res = cn_cbor_encoder_write(buf, 0, bufsize, cn_top);
    cn_cbor_free(cn_top, ct);

    /* Deserialize again */
    cn_top = cn_arr = cn_cbor_decode(buf, res, ct, NULL);

    if (cn_arr->type == CN_CBOR_TAG) {
        cn_arr = cn_arr->first_child;
    }
    /* add body protected header */
    cn_prot = cn_cbor_index(cn_arr, 0);
    _serialize_cbor_protected(sign, (uint8_t *)cn_prot->v.bytes, cn_prot->length + 5, ct, NULL);

    cn_sigs = cn_cbor_index(cn_arr, 3);
    /* Add signature protected headers */
    for (int i = 0; i < sign->num_sigs; i++) {
        const cose_signer_t *signer = sign->sigs[i].signer;
        cn_cbor *cn_sig_prot = cn_cbor_index(cn_cbor_index(cn_sigs, i), 0);
        cose_signer_serialize_protected(signer, (uint8_t *)cn_sig_prot->v.bytes, cn_sig_prot->length + 5, ct, errp);
    }
    cn_cbor_free(cn_top, ct);

    return res;
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_in = cn_cbor_decode(buf, len, ct, errp);
    cn_cbor *cn_start = cn_in;

    if (!(cn_in)) {
        return -1;
    }

    if (cn_in->type == CN_CBOR_TAG && cn_in->v.uint == 98) {
        cn_start = cn_in->first_child;
    }
    if (cn_start->type != CN_CBOR_ARRAY || cn_start->length != 4) {
        return -2;
    }
    cn_cbor *cn_hdr_prot = cn_cbor_index(cn_start, 0);
    cn_cbor *cn_payload = cn_cbor_index(cn_start, 2);
    cn_cbor *cn_sigs = cn_cbor_index(cn_start, 3);

    sign->hdr_prot_ser = cn_hdr_prot->v.bytes;
    sign->hdr_prot_ser_len = cn_hdr_prot->length;
    sign->payload = cn_payload->v.bytes;
    sign->payload_len = cn_payload->length;

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
        psig->hdr_unprotected = cn_cbor_index(cp, 1);
        cn_cbor *sig = cn_cbor_index(cp, 2);
        psig->signature = sig->v.bytes;
        psig->signature_len = sig->length;
        i++;
    }
    cn_cbor_free(cn_in, ct);

    return COSE_OK;
}

size_t cose_sign_get_kid(cose_sign_t *sign, uint8_t idx, const uint8_t **kid)
{
    if (idx < COSE_SIGNATURES_MAX) {
        cn_cbor *cn_unprot = sign->sigs[idx].hdr_unprotected;
        cn_cbor *cn_kid = cn_cbor_mapget_int(cn_unprot, (int)COSE_HDR_KID);
        if (cn_kid) {
            *kid = cn_kid->v.bytes;
            return cn_kid->length;
        }
    }
    *kid = NULL;
    return COSE_ERR_NOMEM;
}

/* Try to verify the structure with a signer and a signature idx */
int cose_sign_verify(cose_sign_t *sign, cose_signer_t *signer, uint8_t idx, cn_cbor_context *ct)
{
    uint8_t buf[2048];
    int res = COSE_OK;
    if (idx >= COSE_SIGNATURES_MAX) {
        return COSE_ERR_NOMEM;
    }
    cose_signature_t *sig = &sign->sigs[idx];
    ssize_t sig_len = _sign_sig_encode(sign, sig, SIG_TYPE_SIGNATURE, buf, sizeof(buf), ct);
    if (sig_len < 0) {
        return sig_len;
    }
    printf("verifying: \n");
    print_bytestr(buf, sig_len);
    printf("\n");
    if (cose_crypto_verify_ed25519(sig->signature, buf, sig_len, signer->x) < 0) {
        res = COSE_ERR_CRYPTO;
    }
    return res;
}
