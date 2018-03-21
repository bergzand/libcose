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
#include "cose/sign.h"
#include "cose/crypto.h"

#define COSE_HDR_SIZE_MAX 32


size_t cose_sign_serialize_sig(cose_sign_t *sign, cose_signature_t *sig, const char* type, uint8_t *buf, size_t buf_size, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    cn_cbor *cn_arr = cn_cbor_array_create(ct, &errp);
    /* Add type string */
    cn_cbor *cn_sign_str = cn_cbor_string_create(type, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_sign_str, &errp);
    /* Add body protected headers */
    cn_cbor *cn_body_prot = cn_cbor_data_create(sign->hdr_prot_ser, sign->hdr_prot_ser_len, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_body_prot, &errp);
    /* Add signer protected headers */
    cn_cbor *cn_signer_prot = cn_cbor_data_create(sig->hdr_protected, sig->hdr_protected_len, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_signer_prot, &errp);
    /* Empty external aad */
    cn_cbor *cn_external = cn_cbor_data_create(sign->ext_aad, sign->ext_aad_len, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_external, &errp);
    /* Add payload */
    cn_cbor *cn_payload = cn_cbor_data_create(sign->payload, sign->payload_len, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_payload, &errp);
    size_t len = cn_cbor_encoder_write(buf, 0, buf_size, cn_arr);
    cn_cbor_free(cn_arr, ct);
    return len;
}

cn_cbor *_cbor_unprotected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    (void)sign;
    return cn_cbor_map_create(ct, errp);
}

void cose_sign_generate_signature(cose_sign_t *sign, const cose_signer_t *signer, cose_signature_t *sig, cn_cbor_context *ct)
{
    /* Needs to contain the full payload, might be necessary to pass it from outside the lib */
    uint8_t buf_cbor[2048];
    size_t sig_struct_len = cose_sign_serialize_sig(sign, sig, SIG_TYPE_SIGNATURE, buf_cbor, sizeof(buf_cbor), ct);
    cose_crypto_sign((uint8_t*)sig->signature, &(sig->signature_len), buf_cbor, sig_struct_len, signer->d);
}


static cn_cbor *_build_cbor_protected(cose_sign_t *sign, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* No support for protected content headers yet, returning an empty map */
    return cn_cbor_map_create(ct, errp);
}

static size_t _serialize_cbor_protected(cose_sign_t *sign, uint8_t *buf, size_t buflen, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *prot = _build_cbor_protected(sign, ct, errp);
    size_t res = cn_cbor_encoder_write(buf, 0, buflen, prot);
    cn_cbor_free(prot, ct);
    return res;
}

void cose_sign_set_payload(cose_sign_t *sign, void *payload, size_t len)
{
    sign->payload = payload;
    sign->payload_len = len;
}

void cose_sign_init(cose_sign_t *sign)
{
    memset(sign, 0, sizeof(cose_sign_t));
}

int cose_sign_add_signer(cose_sign_t *sign, const cose_signer_t *signer, uint8_t *buf, size_t bufsize,  cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* TODO: define status codes */
    if (sign->num_sigs == COSE_SIGNATURES_MAX) {
        return -1;
    }
    /* Serialize protected body header if required */
    if (!(sign->hdr_prot_ser))
    {
        size_t res = _serialize_cbor_protected(sign, buf, bufsize, ct, errp);
        sign->hdr_prot_ser = buf;
        sign->hdr_prot_ser_len = res;
        buf += res;
        bufsize -= res;
    }
    /* Convenience pointer */
    cose_signature_t *sig = &(sign->sigs[sign->num_sigs]);

    /* Add unprotected headers to the signature struct */
    sig->hdr_unprotected = cose_signer_cbor_unprotected(signer, ct, errp);

    /* Serialize signer protected headers */
    size_t prot_size = cose_signer_serialize_protected(signer, buf, bufsize, ct, errp);
    sig->hdr_protected = buf;
    sig->hdr_protected_len = prot_size;
    buf += prot_size;
    bufsize -= prot_size;
    /* Generate signature */
    sig->signature = buf;
    sig->signature_len = bufsize;
    cose_sign_generate_signature(sign, signer, sig, ct);

    sign->num_sigs++;
    return COSE_OK;
}

size_t _cbor_prot(cose_sign_t *sign, cn_cbor *cn_prot, cn_cbor_context *ct)
{
    for (int i=0; i < COSE_SIGN_HDR_PROTECTED_MAX; i++)
    {
        if(sign->hdr_protected[i].id != 0)
        {
            /** Implement things */
        }
    }
    return 0;

}

ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t bufsize, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    /* build cbor payload structure with signer array */
    uint8_t prot_hdr[32];
    size_t prot_len = _serialize_cbor_protected(sign, prot_hdr, sizeof(prot_hdr), ct, errp);
    /* Create protected body header bstr */
    cn_cbor *cn_prot = cn_cbor_data_create(prot_hdr, prot_len, ct, errp);
    /* Create protected body header map */
    cn_cbor *cn_unprot = _cbor_unprotected(sign, ct, errp);
    /* Create payload */
    cn_cbor *cn_payload = cn_cbor_data_create(sign->payload, sign->payload_len, ct, errp);
    /* Create the main array */
    cn_cbor *cn_arr = cn_cbor_array_create(ct, errp);
    /* Create the signature array */
    cn_cbor *cn_sigs = cn_cbor_array_create(ct, errp);
    /* Append everything */
    cn_cbor_array_append(cn_arr, cn_prot, errp);
    cn_cbor_array_append(cn_arr, cn_unprot, errp);
    cn_cbor_array_append(cn_arr, cn_payload, errp);
    cn_cbor_array_append(cn_arr, cn_sigs, errp);

    /* Extend signer array for each signer and place signatures */
    for(int i=0; i < COSE_SIGNATURES_MAX; i++)
    {
        cose_signature_t *sig = &(sign->sigs[i]);
        if (sig->signature_len)
        {
            cn_cbor *cn_sig_prot = cn_cbor_data_create(sig->hdr_protected, sig->hdr_protected_len, ct, errp);
            cn_cbor *cn_sig_unprot = sig->hdr_unprotected;
            cn_cbor *cn_sig = cn_cbor_data_create(sig->signature, sig->signature_len, ct, errp);
            cn_cbor *sig_strct = cn_cbor_array_create(ct, errp);
            cn_cbor_array_append(sig_strct, cn_sig_prot, errp);
            cn_cbor_array_append(sig_strct, cn_sig_unprot, errp);
            cn_cbor_array_append(sig_strct, cn_sig, errp);
            cn_cbor_array_append(cn_sigs, sig_strct, errp);
        }
    }

    /* Serialize array */
    return cn_cbor_encoder_write(buf, 0, bufsize, cn_arr);
}

/* Decode a bytestring to a cose sign struct */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_in = cn_cbor_decode(buf, len, ct, errp);
    cn_cbor *cn_start = cn_in;
    if (!(cn_in))
    {
        return -1;
    }

    if (cn_in->type == CN_CBOR_TAG && cn_in->v.uint == 98)
    {
        cn_start = cn_in->next;
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
    unsigned int i=0;
    for (cp = cn_sigs->first_child; cp; cp = cp->next) {
        if (cp->type != CN_CBOR_ARRAY)
        {
            continue;
        }
        if (i >= COSE_SIGNATURES_MAX)
        {
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

    return COSE_OK;
}

size_t cose_sign_get_kid(cose_sign_t *sign, uint8_t idx, const uint8_t **kid)
{
    if (idx < COSE_SIGNATURES_MAX)
    {
        cn_cbor *cn_unprot = sign->sigs[idx].hdr_unprotected;
        cn_cbor *cn_kid = cn_cbor_mapget_int(cn_unprot, (int)COSE_HDR_KID);
        if(cn_kid) {
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
    if (idx >= COSE_SIGNATURES_MAX)
    {
        return COSE_ERR_NOMEM;
    }
    cose_signature_t *sig = &sign->sigs[idx];
    size_t res = cose_sign_serialize_sig(sign, sig, SIG_TYPE_SIGNATURE, buf, sizeof(buf), ct);
    if (cose_crypto_verify(sig->signature, buf, res, signer->x) < 0 ) {
        return COSE_ERR_CRYPTO;
    }
    return COSE_OK;
}
