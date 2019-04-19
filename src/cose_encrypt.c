/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose/common.h"
#include "cose/crypto.h"
#include "cose/encrypt.h"
#include "cose/intern.h"
#include <stdint.h>
#include <string.h>

static void _place_cbor_protected(cose_encrypt_t *encrypt, nanocbor_encoder_t *arr);
static size_t _encrypt_serialize_protected(const cose_encrypt_t *encrypt, uint8_t *buf, size_t buflen);

static bool _is_encrypt0(cose_encrypt_t *encrypt) {
    return encrypt->flags & COSE_FLAGS_ENCRYPT0;
}

/* Used by encrypt (encode) */
static int _encrypt_build_cbor_enc(cose_encrypt_t *encrypt, nanocbor_encoder_t *enc)
{
    nanocbor_fmt_array(enc, 3);
    /* Add type string */
    if (_is_encrypt0(encrypt)) {
        nanocbor_put_tstr(enc, "Encrypt0");
    }
    else {
        nanocbor_put_tstr(enc, "Encrypt");
    }

    /* Add body protected headers */
    _place_cbor_protected(encrypt, enc);

    /* External aad */
    nanocbor_put_bstr(enc, encrypt->ext_aad, encrypt->ext_aad_len);
    return 0;
}

static bool _encrypt_unprot_to_map(const cose_encrypt_t *encrypt, nanocbor_encoder_t *map)
{
    if (cose_hdr_encode_to_map(encrypt->hdrs.unprot, map)) {
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
    cose_hdr_encode_to_map(encrypt->hdrs.prot, map);
    cose_algo_t algo = cose_encrypt_get_algo(encrypt);
    if (cose_crypto_is_aead(algo)) {
        nanocbor_fmt_int(map, COSE_HDR_ALG);
        nanocbor_fmt_int(map, algo);
    }
    return true;
}

static size_t _encrypt_serialize_protected(const cose_encrypt_t *encrypt, uint8_t *buf, size_t buflen)
{
    nanocbor_encoder_t enc;
    size_t len = cose_hdr_size(encrypt->hdrs.prot);
    if (cose_crypto_is_aead(cose_encrypt_get_algo(encrypt))) {
        len += 1;
    }

    nanocbor_encoder_init(&enc, buf, buflen);
    nanocbor_fmt_map(&enc, len);

    _encrypt_prot_to_map(encrypt, &enc);
    return nanocbor_encoded_len(&enc);
}

static void _place_cbor_protected(cose_encrypt_t *encrypt, nanocbor_encoder_t *arr) {
    size_t slen = _encrypt_serialize_protected(encrypt, NULL, 0);
    nanocbor_put_bstr(arr, arr->cur, slen);
    _encrypt_serialize_protected(encrypt, arr->cur - slen, slen);

  //  else {
  //      nanocbor_put_bstr(arr, encrypt->hdrs.prot.b, encrypt->hdrs.prot_len);
  //  }
}

static size_t _encrypt_unprot_cbor(cose_encrypt_t *encrypt, nanocbor_encoder_t *enc)
{
    size_t len = cose_hdr_size(encrypt->hdrs.unprot);
    /* TODO: split */
    if (cose_crypto_is_aead(cose_encrypt_get_algo(encrypt))) {
        /* Only the nonce */
        len += 1;
    }
    else {
        /* Nonce and algo */
        len += 2;
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

void cose_encrypt_init(cose_encrypt_t *encrypt, uint16_t flags)
{
    memset(encrypt, 0, sizeof(cose_encrypt_t));
    encrypt->flags = flags;
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
        if (_is_encrypt0(encrypt)) {
            nanocbor_fmt_tag(&enc, COSE_ENCRYPT0);
        }
        else {
            nanocbor_fmt_tag(&enc, COSE_ENCRYPT);
        }
    }

    if (_is_encrypt0(encrypt)) {
        nanocbor_fmt_array(&enc, 3);
    }
    else {
        nanocbor_fmt_array(&enc, 4);
    }

    /* Determine size of the body protected headers */
    size_t slen = _encrypt_serialize_protected(encrypt, NULL, 0);
    nanocbor_put_bstr(&enc, buf, slen);
    _encrypt_serialize_protected(encrypt, enc.cur - slen, slen);

    /* Create unprotected body header map */
    _encrypt_unprot_cbor(encrypt, &enc);

    nanocbor_put_bstr(&enc, cipherpos, cipherlen);

    if (!_is_encrypt0(encrypt)) {
        cose_recp_encrypt_to_map(encrypt->recps, encrypt->num_recps, encrypt->cek, 0, &enc);
    }
    *out = buf;
    if (encrypt->algo != COSE_ALGO_DIRECT) {
    /* encode intermediate key with recipient key */
    }
    if (nanocbor_encoded_len(&enc) > len) {
        return COSE_ERR_NOMEM;
    }
    return nanocbor_encoded_len(&enc);
}

///* Retrieve an header from the encrypt object */
//int cose_encrypt_get_protected_hdr(cose_encrypt_t *encrypt, cose_hdr_t *hdr, int32_t key) {
//    nanocbor_value_t it;
//    nanocbor_value_t arr;
//
//    nanocbor_decoder_init(&it, encrypt->buf, encrypt->len);
//
//    if (nanocbor_enter_array(&it, &arr) < 0) {
//        return COSE_ERR_INVALID_CBOR;
//    }
//
//    const uint8_t *buf;
//    size_t len;
//
//    if (nanocbor_get_bstr(&arr, &buf, &len) < 0) {
//        return COSE_ERR_INVALID_CBOR;
//    }
//
//    if (cose_hdr_get_cbor(buf, len, hdr, key)) {
//        return COSE_OK;
//    }
//    else {
//        return COSE_ERR_NOT_FOUND;
//    }
//}
//
//int cose_encrypt_get_unprotected_hdr(cose_encrypt_t *encrypt, cose_hdr_t *hdr, int32_t key) {
//    nanocbor_value_t it;
//    nanocbor_value_t arr;
//
//    nanocbor_decoder_init(&it, encrypt->buf, encrypt->len);
//
//    if (nanocbor_enter_array(&it, &arr) < 0) {
//        return COSE_ERR_INVALID_CBOR;
//    }
//
//    if (nanocbor_skip(&arr) < 0) {
//        return COSE_ERR_INVALID_CBOR;
//    }
//
//    const uint8_t *buf;
//    size_t len;
//
//    if (nanocbor_get_subcbor(&arr, &buf, &len) < 0) {
//        return COSE_ERR_INVALID_CBOR;
//    }
//
//    if (cose_hdr_get_cbor(buf, len, hdr, key)) {
//        return COSE_OK;
//    }
//    else {
//        return COSE_ERR_NOT_FOUND;
//    }
//}

static int _encrypt_decode_get_prot(const cose_encrypt_dec_t *encrypt, const uint8_t **buf, size_t *len)
{
    return cose_cbor_decode_get_prot(encrypt->buf, encrypt->len, buf, len);
}

#if 0
static int _encrypt_decode_get_unprot(const cose_encrypt_dec_t *encrypt, const uint8_t **buf, size_t *len)
{
    return cose_cbor_decode_get_unprot(encrypt->buf, encrypt->len, buf, len);
}
#endif

static bool _is_encrypt0_dec(const cose_encrypt_dec_t *encrypt) {
    return encrypt->flags & COSE_FLAGS_ENCRYPT0;
}

static int _encrypt_decode_get_recps(const cose_encrypt_dec_t *encrypt, const uint8_t **buf, size_t *len)
{
    nanocbor_value_t arr;
    if (_is_encrypt0_dec(encrypt)) {
        return COSE_ERR_NOT_FOUND;
    }

    if (cose_cbor_decode_get_pos(encrypt->buf, encrypt->len, &arr, 3) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_subcbor(&arr, buf, len) < 0 ) {
        return COSE_ERR_INVALID_CBOR;
    }
    return COSE_OK;
}

/* Used by encrypt (decode) */
static int _encrypt_build_cbor_dec(const cose_encrypt_dec_t *encrypt, nanocbor_encoder_t *enc)
{
    nanocbor_fmt_array(enc, 3);
    /* Add type string */
    if (_is_encrypt0_dec(encrypt)) {
        nanocbor_put_tstr(enc, "Encrypt0");
    }
    else {
        nanocbor_put_tstr(enc, "Encrypt");
    }

    /* Add body protected headers */
    const uint8_t *prot;
    size_t prot_len;
    _encrypt_decode_get_prot(encrypt, &prot, &prot_len);
    nanocbor_put_bstr(enc, prot, prot_len);

    /* External aad */
    nanocbor_put_bstr(enc, encrypt->ext_aad, encrypt->ext_aad_len);
    return 0;
}

COSE_ssize_t cose_encrypt_build_dec(const cose_encrypt_dec_t *encrypt, uint8_t *buf, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, len);
    _encrypt_build_cbor_dec(encrypt, &enc);
    return (COSE_ssize_t)nanocbor_encoded_len(&enc);
}

int cose_encrypt_decode_protected(const cose_encrypt_dec_t *encrypt, cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *hdrs;
    size_t len;
    if (cose_cbor_decode_get_prot(encrypt->buf, encrypt->len, &hdrs, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(hdrs, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

int cose_encrypt_decode_unprotected(const cose_encrypt_dec_t *encrypt, cose_hdr_t *hdr, int32_t key)
{
    const uint8_t *hdrs;
    size_t len;
    if (cose_cbor_decode_get_unprot(encrypt->buf, encrypt->len, &hdrs, &len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    if (cose_hdr_decode_from_cbor(hdrs, len, hdr, key)) {
        return COSE_OK;
    }
    return COSE_ERR_NOT_FOUND;
}

int cose_encrypt_decode(cose_encrypt_dec_t *encrypt, uint8_t *buf, size_t len)
{
    nanocbor_value_t it;
    nanocbor_value_t arr;

    encrypt->ext_aad = NULL;
    encrypt->ext_aad_len = 0;
    encrypt->flags = 0;

    encrypt->buf = buf;
    encrypt->len = len;

    nanocbor_decoder_init(&it, buf, len);

    encrypt->flags |= COSE_FLAGS_DECODE;

    /* TODO: Check tag values */
    if (nanocbor_get_type(&it) == NANOCBOR_TYPE_TAG) {
        nanocbor_skip_simple(&it);
    }
    else {
        encrypt->flags |= COSE_FLAGS_UNTAGGED;
    }

    if (nanocbor_get_subcbor(&it, &encrypt->buf, &encrypt->len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }
    nanocbor_decoder_init(&it, encrypt->buf, encrypt->len);

    if (nanocbor_enter_array(&it, &arr) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_container_remaining(&arr) == 3) {
        encrypt->flags |= COSE_FLAGS_ENCRYPT0;
    }
    else if (nanocbor_container_remaining(&arr) != 4) {
        return COSE_ERR_INVALID_CBOR;
    }

    /* Prot headers and unprot headers */
    /* NOLINTNEXTLINE(misc-redundant-expression) */
    if (nanocbor_skip(&arr) < 0 || nanocbor_skip(&arr) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    if (nanocbor_get_null(&arr) >= 0) {
        /* Zero payload length, thus external payload */
        encrypt->flags |= COSE_FLAGS_EXTDATA;
        encrypt->payload = NULL;
        encrypt->payload_len = 0;
    }
    else if (nanocbor_get_bstr(&arr, (const uint8_t **)&encrypt->payload,
                               &encrypt->payload_len) < 0) {
        return COSE_ERR_INVALID_CBOR;
    }

    return COSE_OK;
}

bool cose_encrypt_recp_iter(const cose_encrypt_dec_t *encrypt,
                            cose_recp_dec_t *recp)
{
    if(_is_encrypt0_dec(encrypt)) {
        return false;
    }
    const uint8_t *buf = NULL;
    size_t len = 0;
    nanocbor_value_t tmp;
    nanocbor_value_t arr;

    _encrypt_decode_get_recps(encrypt, &buf, &len);
    nanocbor_decoder_init(&tmp, buf, len);
    nanocbor_enter_array(&tmp, &arr);

    while ((recp->buf >= arr.cur) && !nanocbor_at_end(&arr)) {
        nanocbor_skip(&arr);
    }
    if (!nanocbor_at_end(&arr)) {
        const uint8_t *recp_buf;
        size_t recp_len = 0;
        if (nanocbor_get_subcbor(&arr, &recp_buf, &recp_len) < 0) {
            return false;
        }
        cose_recp_decode_init(recp, recp_buf, recp_len);
        return true;
    }
    return false;
}

/* Try to decrypt a packet */
int cose_encrypt_decrypt(const cose_encrypt_dec_t *encrypt,
                         const cose_recp_dec_t *recp,
                         const cose_key_t *key, uint8_t *buf,
                         size_t len, uint8_t *payload, size_t *payload_len)
{
    if (recp == NULL && !_is_encrypt0_dec(encrypt)) {
        return COSE_ERR_CRYPTO;
    }

    COSE_ssize_t aad_len = cose_encrypt_build_dec(encrypt, buf, len);
    if (aad_len < 0) {
       return (int)aad_len;
    }
    cose_hdr_t nonce_hdr;
    if (cose_encrypt_decode_unprotected(encrypt, &nonce_hdr, COSE_HDR_IV) < 0) {
        return COSE_ERR_CRYPTO;
    }

    if (nonce_hdr.type != COSE_HDR_TYPE_BSTR) {
        return COSE_ERR_INVALID_CBOR;
    }

    const uint8_t *nonce = nonce_hdr.v.data;

    cose_algo_t algo;
    cose_hdr_t algo_hdr;

    if (cose_encrypt_decode_protected(encrypt, &algo_hdr, COSE_HDR_ALG) < 0) {
        return COSE_ERR_CRYPTO;
    }

    if (algo_hdr.type != COSE_HDR_TYPE_INT) {
        return COSE_ERR_INVALID_CBOR;
    }

    algo = algo_hdr.v.value;

    if (algo != key->algo) {
        return COSE_ERR_CRYPTO;
    }

    const uint8_t *cek = key->d;

    return cose_crypto_aead_decrypt(payload, payload_len, encrypt->payload, encrypt->payload_len, buf, aad_len, nonce, cek, algo);
}
