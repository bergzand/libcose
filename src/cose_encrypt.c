/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose.h"
#include "cose/cbor.h"
#include "cose/crypto.h"
#include "cose/encrypt.h"
#include "cose/intern.h"
#include <cn-cbor/cn-cbor.h>
#include <stdint.h>
#include <string.h>

static bool _is_encrypt0(cose_encrypt_t *encrypt) {
    (void)encrypt;
    return false;
}

static cn_cbor *_encrypt_build_cbor_enc(cose_encrypt_t *encrypt, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cn_arr = cn_cbor_array_create(ct, errp);
    if (!cn_arr) {
        return NULL;
    }
    /* Add type string */
    cn_cbor *cn_enc_str = cn_cbor_string_create("Encrypt", ct, errp);
    CBOR_CATCH_ERR(cn_enc_str, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_enc_str, errp);

    /* Add body protected headers */
    cn_cbor *cn_prot = cn_cbor_data_create(encrypt->hdr_prot_ser, encrypt->hdr_prot_ser_len, ct, errp);
    CBOR_CATCH_ERR(cn_prot, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_prot, errp);

    /* External aad */
    cn_cbor *cn_external = cn_cbor_data_create(encrypt->ext_aad, encrypt->ext_aad_len, ct, errp);
    CBOR_CATCH_ERR(cn_external, cn_arr, ct);
    cn_cbor_array_append(cn_arr, cn_external, errp);
    return cn_arr;
}

static bool _encrypt_unprot_to_map(const cose_encrypt_t *encrypt, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    if (!cose_hdr_add_to_map(encrypt->hdrs, COSE_SIG_HDR_MAX, map, false, ct, errp)) {
        return false;
    }
    cose_algo_t algo = cose_encrypt_get_algo(encrypt);
    if (!cose_crypto_is_aead(algo)) {
        cn_cbor *cn_algo = cn_cbor_int_create(algo, ct, errp);
        if(!cn_cbor_mapput_int(map, COSE_HDR_ALG, cn_algo, ct, errp)) {
            cn_cbor_free(cn_algo, ct);
            return false;
        }
    }
    if (encrypt->nonce) {
        cn_cbor *cn_nonce = cn_cbor_data_create(encrypt->nonce,
                                                cose_crypto_aead_nonce_size(algo),
                                                ct, errp);
        if (!cn_cbor_mapput_int(map, COSE_HDR_IV, cn_nonce, ct, errp)) {
            cn_cbor_free(cn_nonce, ct);
            return false;
        }
    }
    return true;
}

/* Add the body protected headers to a map */
static bool _encrypt_prot_to_map(const cose_encrypt_t *encrypt, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    if (!cose_hdr_add_to_map(encrypt->hdrs, COSE_SIG_HDR_MAX, map, true, ct, errp)) {
        return false;
    }
    cose_algo_t algo = cose_encrypt_get_algo(encrypt);
    if (cose_crypto_is_aead(algo)) {
        cn_cbor *cn_algo = cn_cbor_int_create(algo, ct, errp);
        if(!cn_cbor_mapput_int(map, COSE_HDR_ALG, cn_algo, ct, errp)) {
            cn_cbor_free(cn_algo, ct);
            return false;
        }
    }
    return true;
}

static size_t _encrypt_serialize_protected(const cose_encrypt_t *encrypt, uint8_t *buf, size_t buflen,
                                           cn_cbor_context *ct, cn_cbor_errback *errp)
{
    size_t res = 0;
    cn_cbor *cn_prot = cn_cbor_map_create(ct, errp);
    if (!cn_prot) {
        return 0;
    }
    if (!_encrypt_prot_to_map(encrypt, cn_prot, ct, errp)) {
        cn_cbor_free(cn_prot, ct);
        return 0;
    }
    /* If AEAD, add the algo to the protected headers */
    res = cn_cbor_encoder_write(buf, 0, buflen, cn_prot);
    cn_cbor_free(cn_prot, ct);
    return res;
}

static cn_cbor* _encrypt_unprot_cbor(cose_encrypt_t *encrypt, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *map = cn_cbor_map_create(ct, errp);

    if (!_encrypt_unprot_to_map(encrypt, map, ct, errp)) {
        cn_cbor_free(map, ct);
        return NULL;
    }
    return map;
}

ssize_t cose_encrypt_build_enc(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    cn_cbor *cn_enc = _encrypt_build_cbor_enc(encrypt, ct, &errp);
    if (!cn_enc) {
        return cose_intern_err_translate(&errp);
    }
    size_t res = cn_cbor_encoder_write(buf, 0, len, cn_enc);
    cn_cbor_free(cn_enc, ct);
    return (ssize_t)res;

}

cose_algo_t cose_encrypt_get_algo(const cose_encrypt_t *encrypt)
{
    return encrypt->algo == COSE_ALGO_DIRECT ? encrypt->recps[0].key->algo : encrypt->algo;
}

static ssize_t _encrypt_payload(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, uint8_t *nonce, uint8_t **out, cn_cbor_context *ct)
{
    cose_algo_t algo = cose_encrypt_get_algo(encrypt);
    cn_cbor_errback errp;
    encrypt->nonce = nonce;
    if (cose_crypto_is_aead(algo)) {
        printf("Current algo %d is aead\n", algo);
        /* Determine length of the protected headers */

        /* Protected enc structure with nonsense protected headers */
        uint8_t *encp = buf;
        ssize_t enc_size = cose_encrypt_build_enc(encrypt, buf, len, ct);
        if (enc_size < 0) {
            return enc_size;
        }
        buf += enc_size;
        cn_cbor *cn_arr = cn_cbor_decode(encp, enc_size, ct, &errp);
        if (!cn_arr)
        {
            return cose_intern_err_translate(&errp);
        }
        cn_cbor *cn_prot = cn_cbor_index(cn_arr, 1);

        if (!(_encrypt_serialize_protected(encrypt,
                                    (uint8_t *)cn_prot->v.bytes, (size_t)cn_prot->length + 5,
                                    ct, &errp))) {
            cn_cbor_free(cn_arr, ct);
            return cose_intern_err_translate(&errp);
        }
        /* At this point we have our AAD at encp with length enc_size and the
         * encrypt->payload@encrypt->payload_len to feed our algo */
        size_t cipherlen = 0;
        printf("AAD_HEX: \n");
        print_bytestr(encp, enc_size);
        printf("\n");
        cn_cbor_free(cn_arr, ct);
        cose_crypto_aead(buf, &cipherlen, encrypt->payload, encrypt->payload_len, encp, enc_size, NULL, nonce, encrypt->cek, algo);
        *out = buf;
        return cipherlen;
    }
    return 0;
}

void cose_encrypt_init(cose_encrypt_t *encrypt)
{
    memset(encrypt, 0, sizeof(cose_encrypt_t));
}

void cose_encrypt_set_payload(cose_encrypt_t *encrypt, const void *payload, size_t len)
{
    encrypt->payload = payload;
    encrypt->payload_len = len;
}

void cose_encrypt_set_algo(cose_encrypt_t *encrypt, cose_algo_t algo)
{
    encrypt->algo = algo;
}

int cose_encrypt_add_recipient(cose_encrypt_t *encrypt, const cose_key_t *key)
{
    /* TODO: define status codes */
    if (encrypt->num_recps == COSE_RECIPIENTS_MAX) {
        return COSE_ERR_NOMEM;
    }
    /* Convenience pointer */
    cose_recp_t *recp = &(encrypt->recps[encrypt->num_recps]);
    recp->key = key;

    return encrypt->num_recps++;
}

ssize_t cose_encrypt_encode(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, uint8_t *nonce, uint8_t **out, cn_cbor_context *ct)
{
    cn_cbor_errback errp;
    (void)errp;
    /* The buffer here is used to contain dummy data a number of times */
    uint8_t *bufptr = buf;

    /* Generate intermediate key
     * or get it from the first recipient if it is direct */
    if (encrypt->algo == COSE_ALGO_DIRECT) {
       encrypt->cek = encrypt->recps[0].key->d;
    }
    else {
        /* Generate intermediate key */
        encrypt->cek = buf;
        buf += cose_crypto_keygen(buf, len, encrypt->algo);
    }

    /* Determine size of the body protected headers */
    size_t encrypt_prot_len = _encrypt_serialize_protected(encrypt, buf, len, ct, &errp);
    if (!encrypt_prot_len) {
        return cose_intern_err_translate(&errp);
    }
    encrypt->hdr_prot_ser_len = encrypt_prot_len;
    encrypt->hdr_prot_ser = buf;

    /* Build ciphertext */
    uint8_t *cipherpos = 0;
    ssize_t cipherlen = _encrypt_payload(encrypt, buf, len - (bufptr - buf), nonce, &cipherpos, ct);
    if (cipherlen < 0) {
        return cipherlen;
    }
    buf = cipherpos + cipherlen;

    /* Now we have the ciphertext for the structure. Key at encrypt->cek in
     * case we need to encrypt it for recps */
    cn_cbor *cn_arr, *cn_top;
    cn_top = cn_arr = cn_cbor_array_create(ct, &errp);
    if (!cn_arr) {
        return cose_intern_err_translate(&errp);
    }
    cn_cbor *cn_prot = cn_cbor_data_create(encrypt->hdr_prot_ser, encrypt->hdr_prot_ser_len, ct, &errp);
    CBOR_CATCH_RET_ERR(cn_prot, cn_arr, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_prot, &errp);

    /* Create unprotected body header map */
    cn_cbor *cn_unprot = _encrypt_unprot_cbor(encrypt, ct, &errp);
    CBOR_CATCH_RET_ERR(cn_unprot, cn_arr, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_unprot, &errp);

    cn_cbor *cn_cipher = cn_cbor_data_create(cipherpos, cipherlen, ct, &errp);
    CBOR_CATCH_RET_ERR(cn_cipher, cn_arr, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_cipher, &errp);

    cn_cbor *cn_recps = cose_recp_encrypt_to_map(encrypt->recps, encrypt->num_recps, encrypt->cek, 0, ct, &errp);
    CBOR_CATCH_RET_ERR(cn_recps, cn_arr, ct, &errp);
    cn_cbor_array_append(cn_arr, cn_recps, &errp);

    if (!(cose_flag_isset(encrypt->flags, COSE_FLAGS_UNTAGGED))) {
        cn_top = cn_cbor_tag_create(
            _is_encrypt0(encrypt) ? COSE_ENCRYPT0 : COSE_ENCRYPT,
            cn_arr,
            ct,
            &errp);
        CBOR_CATCH_RET_ERR(cn_top, cn_arr, ct, &errp);
    }
    size_t res = cn_cbor_encoder_write(buf, 0, len - (buf - bufptr), cn_top);
    /* free cbor structure */
    cn_cbor_free(cn_top, ct);

    /* Deserialize again to fill protected headers */
    cn_top = cn_arr = cn_cbor_decode(buf, res, ct, &errp);
    if (!cn_top) {
        return cose_intern_err_translate(&errp);
    }

    if (cn_top->type == CN_CBOR_TAG) {
        cn_arr = cn_top->first_child;
    }
    /* add body protected header */
    cn_prot = cn_cbor_index(cn_arr, 0);
    if (!(_encrypt_serialize_protected(encrypt, (uint8_t *)cn_prot->v.bytes, (size_t)cn_prot->length + 5, ct, &errp))) {
        cn_cbor_free(cn_top, ct);
        return cose_intern_err_translate(&errp);
    }

    cn_cbor_free(cn_top, ct);

    *out = buf;

    if (encrypt->algo != COSE_ALGO_DIRECT) {
    /* encode intermediate key with recipient key */
    }
    return res;
}

