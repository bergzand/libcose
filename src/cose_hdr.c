/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose_defines.h"
#include "cose/hdr.h"
#include <nanocbor/nanocbor.h>
#include <string.h>

/* Appends the header struct to the given cbor map */
static int _hdr_encode_to_cbor_map(const cose_hdr_t *hdr, nanocbor_encoder_t *map)
{
    int res = 0;
    nanocbor_fmt_int(map, hdr->key);
    switch (hdr->type) {
        case COSE_HDR_TYPE_INT:
            nanocbor_fmt_int(map, hdr->v.value);
            break;
        case COSE_HDR_TYPE_TSTR:
            nanocbor_put_tstr(map, hdr->v.str);
            break;
        case COSE_HDR_TYPE_BSTR:
            nanocbor_put_bstr(map, hdr->v.data, hdr->len);
            break;
        case COSE_HDR_TYPE_CBOR:
        case COSE_HDR_TYPE_UNDEF:
            /* Not supported */
            res = -1;
            break;
    }
    return res;
}

/* Convert a map value to a cose_hdr struct */
static bool _hdr_decode_from_cbor_map(cose_hdr_t *hdr, int32_t key,
                                      nanocbor_value_t *val)
{
    hdr->key = key;
    hdr->type = COSE_HDR_TYPE_UNDEF;
    int type = nanocbor_get_type(val);

    if (type == NANOCBOR_TYPE_NINT || type == NANOCBOR_TYPE_UINT) {
        hdr->type = COSE_HDR_TYPE_INT;
        nanocbor_get_int32(val, &hdr->v.value);
        return true;
    }
    if (type == NANOCBOR_TYPE_TSTR) {
        hdr->type = COSE_HDR_TYPE_TSTR;
        nanocbor_get_tstr(val, (const uint8_t **)&hdr->v.str, &hdr->len);
        return true;
    }
    if (type == NANOCBOR_TYPE_BSTR) {
        hdr->type = COSE_HDR_TYPE_BSTR;
        nanocbor_get_bstr(val, &hdr->v.data, &hdr->len);
        return true;
    }
    if (type == NANOCBOR_TYPE_MAP || type == NANOCBOR_TYPE_ARR || type == NANOCBOR_TYPE_TAG) {
        hdr->type = COSE_HDR_TYPE_CBOR;
        nanocbor_get_subcbor(val, &hdr->v.cbor, &hdr->len);
        return true;
    }
    return false;
}

/* formatters */
void cose_hdr_format_int(cose_hdr_t *hdr, int32_t key, int32_t value)
{
    hdr->type = COSE_HDR_TYPE_INT;
    hdr->key = key;
    hdr->v.value = value;
}

void cose_hdr_format_string(cose_hdr_t *hdr, int32_t key, const char *str)
{
    hdr->type = COSE_HDR_TYPE_TSTR;
    hdr->key = key;
    hdr->v.str = str;
}

void cose_hdr_format_data(cose_hdr_t *hdr, int32_t key, const uint8_t *data, size_t len)
{
    hdr->type = COSE_HDR_TYPE_BSTR;
    hdr->key = key;
    hdr->v.data = data;
    hdr->len = len;
}

void cose_hdr_insert(cose_hdr_t **hdrs, cose_hdr_t *nhdr)
{
    nhdr->next = *hdrs;
    *hdrs = nhdr;
}

int cose_hdr_encode_to_map(const cose_hdr_t *hdr, nanocbor_encoder_t *map)
{
    int err = 0;
    for (; hdr; hdr = hdr->next) {
        err = _hdr_encode_to_cbor_map(hdr, map);
    }
    return err;
}

/* Retrieve header from cose encoder structure */
bool cose_hdr_get_hdr(cose_hdr_t *hdrs, cose_hdr_t *hdr, int32_t key)
{
    for (cose_hdr_t *h = hdrs; h; h = h->next) {
        if (h->key == key) {
            memcpy(hdr, h, sizeof(cose_hdr_t));
            return true;
        }
    }
    return false;
}

bool cose_hdr_get_protected(cose_headers_t *headers, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get_hdr(headers->prot, hdr, key);
}

bool cose_hdr_get_unprotected(cose_headers_t *headers, cose_hdr_t *hdr, int32_t key)
{
    return cose_hdr_get_hdr(headers->unprot, hdr, key);
}

bool cose_hdr_get(cose_headers_t *headers, cose_hdr_t *hdr,
        int32_t key)
{
    if (cose_hdr_get_protected(headers, hdr, key) ||
            cose_hdr_get_unprotected(headers, hdr, key)) {
        return true;
    }
    return false;
}


/* Number of linked headers */
size_t cose_hdr_size(const cose_hdr_t *hdr)
{
    size_t res = 0;
    for (; hdr; hdr = hdr->next) {
        res++;
    }
    return res;
}

bool cose_hdr_decode_from_cbor(const uint8_t *buf, size_t len, cose_hdr_t *hdr, int32_t key)
{
    nanocbor_value_t it;
    nanocbor_value_t map;
    nanocbor_decoder_init(&it, buf, len);
    if (nanocbor_enter_map(&it, &map) < 0) {
        return false;
    }
    while(!nanocbor_at_end(&map)) {
        int32_t ckey;
        if (nanocbor_get_int32(&map, &ckey) >= 0){
            if (ckey == key) {
                return _hdr_decode_from_cbor_map(hdr, ckey, &map);
            }
            nanocbor_skip(&map);
        }
        else {
            break;
        }
    }
    return false;
}

