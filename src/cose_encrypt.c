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
#include <stdint.h>
#include <string.h>
static void _place_cbor_protected(cose_encrypt_t *encrypt, nanocbor_encoder_t *arr);
static size_t _encrypt_serialize_protected(const cose_encrypt_t *encrypt, uint8_t *buf, size_t buflen);

//static bool _is_encrypt0(cose_encrypt_t *encrypt) {
//    (void)encrypt;
//    return false;
//}

static int _encrypt_build_cbor_enc(cose_encrypt_t *encrypt, nanocbor_encoder_t *enc)
{
    nanocbor_fmt_array(enc, 3);
    /* Add type string */
    nanocbor_put_tstr(enc, "Encrypt");

    /* Add body protected headers */
    _place_cbor_protected(encrypt, enc);

    /* External aad */
    nanocbor_put_bstr(enc, encrypt->ext_aad, encrypt->ext_aad_len);
    return 0;
}

static bool _encrypt_unprot_to_map(const cose_encrypt_t *encrypt, nanocbor_encoder_t *map)
{
    if (cose_hdr_add_to_map(encrypt->hdrs.unprot.c, map)) {
        return false;
    }
    cose_algo_t algo = cose_encrypt_get_algo(encrypt);
    if (!cose_crypto_is_aead(algo)) {
        nanocbor_fmt_int(map, COSE_HDR_ALG);
        nanocbor_fmt_int(map, algo);
    }
    if (encrypt->nonce) {
        nanocbor_fmt_int(map, COSE_HDR_IV);
        nanocbor_put_bstr(map, encrypt->nonce, cose_crypto_aead_nonce_size(algo));
    }
    return true;
}

/* Add the body protected headers to a map */
static bool _encrypt_prot_to_map(const cose_encrypt_t *encrypt, nanocbor_encoder_t *map)
{
    cose_hdr_add_to_map(encrypt->hdrs.prot.c, map);
    if (cose_flag_isset(encrypt->flags, COSE_FLAGS_ENCODE)) {
        cose_algo_t algo = cose_encrypt_get_algo(encrypt);
        if (cose_crypto_is_aead(algo)) {
            nanocbor_fmt_int(map, COSE_HDR_ALG);
            nanocbor_fmt_int(map, algo);
        }
    }
    return true;
}

static size_t _encrypt_serialize_protected(const cose_encrypt_t *encrypt, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    size_t len = cose_hdr_size(encrypt->hdrs.prot.c);
    if (cose_flag_isset(encrypt->flags, COSE_FLAGS_ENCODE)) {
        if (cose_crypto_is_aead(cose_encrypt_get_algo(encrypt))) {
            len += 1;
        }
    }
    nanocbor_encoder_init(&enc, buf, buflen);
    nanocbor_fmt_map(&enc, len);

    _encrypt_prot_to_map(encrypt, &enc);
    return nanocbor_encoded_len(&enc);
}

static void _place_cbor_protected(cose_encrypt_t *encrypt, nanocbor_encoder_t *arr) {
    if (cose_flag_isset(encrypt->flags, COSE_FLAGS_ENCODE)) {
        size_t slen = _encrypt_serialize_protected(encrypt, NULL, 0);
        nanocbor_put_bstr(arr, arr->cur, slen);
        _encrypt_serialize_protected(encrypt, arr->cur - slen, slen);
    }
    else {
        nanocbor_put_bstr(arr, encrypt->hdrs.prot.b, encrypt->hdrs.prot_len);
    }
}

static size_t _encrypt_unprot_cbor(cose_encrypt_t *encrypt, nanocbor_encoder_t *enc)
{
    size_t len = cose_hdr_size(encrypt->hdrs.unprot.c);
    /* TODO: split */
    if (cose_flag_isset(encrypt->flags, COSE_FLAGS_ENCODE)) {
        if (cose_crypto_is_aead(cose_encrypt_get_algo(encrypt))) {
            /* Only the nonce */
            len += 1;
        }
        else {
            /* Nonce and algo */
            len += 2;
        }
    }

    nanocbor_fmt_map(enc, len);
    _encrypt_unprot_to_map(encrypt, enc);
    return 0;
}

COSE_ssize_t cose_encrypt_build_enc(cose_encrypt_t *encrypt, uint8_t *buf, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, len);
    _encrypt_build_cbor_enc(encrypt, &enc);
    return (COSE_ssize_t)nanocbor_encoded_len(&enc);
}

cose_algo_t cose_encrypt_get_algo(const cose_encrypt_t *encrypt)
{
    cose_algo_t res;
    if (encrypt->recps[0].key) {
        res = encrypt->recps[0].key->algo;
    }
    else {
        cose_hdr_t hdr;
        if (!cose_hdr_get((cose_headers_t*)&encrypt->recps[0].hdrs, &hdr,  COSE_HDR_ALG)) {
            res = COSE_ALGO_NONE;
        }
        else {
            res = hdr.v.value;
        }
    }

    return encrypt->algo == COSE_ALGO_DIRECT ? res : encrypt->algo;
}

static COSE_ssize_t _encrypt_build_aad(cose_encrypt_t *encrypt, uint8_t *buf, size_t len)
{
    COSE_ssize_t enc_size = cose_encrypt_build_enc(encrypt, buf, len);
    if (enc_size < 0) {
        return enc_size;
    }
    return enc_size;
}

static COSE_ssize_t _encrypt_payload(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, uint8_t *nonce, uint8_t **out)
{
    cose_algo_t algo = cose_encrypt_get_algo(encrypt);
    encrypt->nonce = nonce;
    if (cose_crypto_is_aead(algo)) {
        /* Protected enc structure with nonsense protected headers */
        uint8_t *encp = buf;
        COSE_ssize_t enc_size = _encrypt_build_aad(encrypt, encp, len);
        if (enc_size < 0) {
            return enc_size;
        }
        buf += enc_size;
        /* At this point we have our AAD at encp with length enc_size and the
         * encrypt->payload@encrypt->payload_len to feed our algo */
        size_t cipherlen = 0;
        cose_crypto_aead_encrypt(buf, &cipherlen, encrypt->payload, encrypt->payload_len, encp, enc_size, NULL, nonce, encrypt->cek, algo);
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

COSE_ssize_t cose_encrypt_encode(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, uint8_t *nonce, uint8_t **out)
{
    /* The buffer here is used to contain dummy data a number of times */
    uint8_t *bufptr = buf;
    encrypt->flags |= COSE_FLAGS_ENCODE;

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

    /* Build ciphertext */
    uint8_t *cipherpos = 0;
    COSE_ssize_t cipherlen = _encrypt_payload(encrypt, buf, len - (bufptr - buf), nonce, &cipherpos);
    if (cipherlen < 0) {
        return cipherlen;
    }
    buf = cipherpos + cipherlen;

    /* Now we have the ciphertext for the structure. Key at encrypt->cek in
     * case we need to encrypt it for recps */
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, len);

    if (!(cose_flag_isset(encrypt->flags, COSE_FLAGS_UNTAGGED))) {
        nanocbor_fmt_tag(&enc, COSE_ENCRYPT);
    }

    nanocbor_fmt_array(&enc, 4);

    /* Determine size of the body protected headers */
    size_t slen = _encrypt_serialize_protected(encrypt, NULL, 0);
    nanocbor_put_bstr(&enc, buf, slen);
    _encrypt_serialize_protected(encrypt, enc.cur - slen, slen);

    /* Create unprotected body header map */
    _encrypt_unprot_cbor(encrypt, &enc);

    nanocbor_put_bstr(&enc, cipherpos, cipherlen);

    cose_recp_encrypt_to_map(encrypt->recps, encrypt->num_recps, encrypt->cek, 0, &enc);
    *out = buf;
    if (encrypt->algo != COSE_ALGO_DIRECT) {
    /* encode intermediate key with recipient key */
    }
    if (nanocbor_encoded_len(&enc) > len) {
        return COSE_ERR_NOMEM;
    }
    return nanocbor_encoded_len(&enc);
}

int cose_encrypt_decode(cose_encrypt_t *encrypt, uint8_t *buf, size_t len)
{
    nanocbor_value_t it;
    nanocbor_value_t arr;

    nanocbor_decoder_init(&it, buf, len);

    encrypt->flags |= COSE_FLAGS_DECODE;

    /* Check tag values */
    if (nanocbor_get_type(&it) == NANOCBOR_TYPE_TAG) {
        nanocbor_skip_simple(&it);
    }
    if (nanocbor_enter_array(&it, &arr) < 0 ||
            nanocbor_container_remaining(&arr) != 4) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_bstr(&arr, &encrypt->hdrs.prot.b, &encrypt->hdrs.prot_len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_type(&arr) !=  NANOCBOR_TYPE_MAP) {
        return COSE_ERR_INVALID_CBOR;
    }

    encrypt->hdrs.unprot.b = arr.start;

    nanocbor_skip(&arr);

    encrypt->hdrs.unprot_len = arr.start - encrypt->hdrs.unprot.b;

    cose_hdr_t alg_hdr;
    if (!cose_hdr_get(&encrypt->hdrs, &alg_hdr, COSE_HDR_ALG)) {
        return COSE_ERR_INVALID_CBOR;
    }
    encrypt->algo = alg_hdr.v.value;

    nanocbor_get_bstr(&arr, &encrypt->payload, &encrypt->payload_len);

    if (!encrypt->payload_len) {
        /* Zero payload length, thus external payload */
        encrypt->flags |= COSE_FLAGS_EXTDATA;
        encrypt->payload = NULL;
    }

    /* Recipients */
    if (nanocbor_get_type(&arr) == NANOCBOR_TYPE_ARR) {
        nanocbor_value_t cp;
        nanocbor_enter_array(&arr, &cp);
        unsigned int i = 0;
        while (!nanocbor_at_end(&cp)) {
            nanocbor_value_t recp;
            cose_recp_t *precp = &(encrypt->recps[i]);
            if (i >= COSE_RECIPIENTS_MAX) {
                break;
            }
            if (nanocbor_get_type(&cp) != NANOCBOR_TYPE_ARR) {
                return COSE_ERR_INVALID_CBOR;
            }
            if (nanocbor_enter_array(&it, &arr) < 0 ||
                (nanocbor_container_remaining(&arr) != 4 &&
                 nanocbor_container_remaining(&arr) != 3)) {
                    return COSE_ERR_INVALID_CBOR;
            }

            nanocbor_enter_array(&cp, &recp);

            /* Protected headers */
            nanocbor_get_bstr(&recp, &precp->hdrs.prot.b, &precp->hdrs.prot_len);

            /* Unprotected headers */
            if (nanocbor_get_type(&recp) != NANOCBOR_TYPE_MAP) {
                return COSE_ERR_INVALID_CBOR;
            }
            precp->hdrs.unprot.b = recp.start;

            nanocbor_skip(&recp);
            precp->hdrs.unprot_len = recp.start - precp->hdrs.unprot.b;
            if (nanocbor_get_bstr(&recp, &precp->skey, &precp->key_len) <0 ) {
                return COSE_ERR_INVALID_CBOR;
            }

            if (!precp->key_len) {
                precp->skey = NULL;
            }
            cose_hdr_t recp_alg;

            if (cose_hdr_get(&precp->hdrs, &recp_alg, COSE_HDR_ALG) && recp_alg.v.value == COSE_ALGO_DIRECT) {
                /* Mark cose encrypt as direct */
                encrypt->algo = COSE_ALGO_DIRECT;
            }
            i++;
        }
        encrypt->num_recps = i;
    }
    return COSE_OK;
}


/* Try to decrypt a packet */
int cose_encrypt_decrypt(cose_encrypt_t *encrypt, cose_key_t *key, unsigned idx, uint8_t *buf, size_t len, uint8_t *payload, size_t *payload_len)
{
    if (idx >= COSE_RECIPIENTS_MAX) {
        return COSE_ERR_NOMEM;
    }
    cose_recp_t *recp = &encrypt->recps[idx];
    (void)recp;
    COSE_ssize_t aad_len = cose_encrypt_build_enc(encrypt, buf, len);
    if (aad_len < 0) {
       return (int)aad_len;
    }
    cose_hdr_t nonce_hdr;
    if (!cose_hdr_get(&encrypt->hdrs, &nonce_hdr, COSE_HDR_IV)) {
        return COSE_ERR_CRYPTO;
    }
    const uint8_t *nonce = nonce_hdr.v.data;
    cose_algo_t algo = encrypt->algo;
    const uint8_t *cek = encrypt->cek;
    if (algo == COSE_ALGO_DIRECT) {
        cose_hdr_t algo_hdr;
        cose_hdr_get(&encrypt->hdrs, &algo_hdr, COSE_HDR_ALG);
        algo = algo_hdr.v.value;
        cek = key->d;
    }
    return cose_crypto_aead_decrypt(payload, payload_len, encrypt->payload, encrypt->payload_len, buf, aad_len, nonce, cek, algo);
}
