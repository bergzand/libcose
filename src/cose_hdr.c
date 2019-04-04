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
#include "cose/hdr.h"
#include <cbor.h>

/* Appends the header the given cbor map */
CborError cose_hdr_to_cbor_map(const cose_hdr_t *hdr, CborEncoder *map)
{
    CborError err = cbor_encode_int(map, hdr->key);
    switch (hdr->type) {
        case COSE_HDR_TYPE_INT:
            err = cbor_encode_int(map, hdr->v.value);
            break;
        case COSE_HDR_TYPE_TSTR:
            err = cbor_encode_text_stringz(map, hdr->v.str);
            break;
        case COSE_HDR_TYPE_BSTR:
            err = cbor_encode_byte_string(map, hdr->v.data, hdr->len);
            break;
        case COSE_HDR_TYPE_CBOR:
            /* Not supported */
            break;
    }
    return err;
}

/* Convert a map key to a cose_hdr struct */
bool cose_hdr_from_cbor_map(cose_hdr_t *hdr, const CborValue *key)
{
    CborValue val = *key;
    if (!cbor_value_is_integer(&val)) {
        return false;
    }
    int64_t value;
    cbor_value_get_int64(&val, &value);
    /* TODO: bounds check */
    hdr->key = (int32_t)value;
    cbor_value_advance_fixed(&val);
    switch (cbor_value_get_type(&val)) {
        case CborIntegerType:
            {
                cbor_value_get_int64(&val, &value);
                hdr->v.value = (int32_t)value;
                hdr->type = COSE_HDR_TYPE_INT;
            }
            break;
        case CborTextStringType:
            cose_cbor_get_string(&val, (const uint8_t **)&hdr->v.str, &hdr->len);
            hdr->type = COSE_HDR_TYPE_TSTR;
            break;
        case CborByteStringType:
            cose_cbor_get_string(&val, &hdr->v.data, &hdr->len);
            hdr->type = COSE_HDR_TYPE_BSTR;
            break;
        case CborArrayType:
        case CborMapType:
        case CborTagType:
            /* Todo: copy map */
            hdr->type = COSE_HDR_TYPE_CBOR;
            break;
        default:
            return false;
    }
    return true;
}

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

CborError cose_hdr_add_to_map(const cose_hdr_t *hdr, CborEncoder *map)
{
    CborError err = 0;
    for (; hdr; hdr = hdr->next) {
        err = cose_hdr_to_cbor_map(hdr, map);
    }
    return err;
}

size_t cose_hdr_size(const cose_hdr_t *hdr)
{
    size_t res = 0;
    for (; hdr; hdr = hdr->next) {
        res++;
    }
    return res;
}

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

bool cose_hdr_get_cbor(const uint8_t *buf, size_t len, cose_hdr_t *hdr, int32_t key)
{
    CborParser p;
    CborValue it;
    CborValue map;
    cbor_parser_init(buf, len, CborValidateStrictMode, &p, &it);
    if (!cbor_value_is_map(&it)) {
        return false;
    }
    cbor_value_enter_container(&it, &map);
    while(!cbor_value_at_end(&map)) {
        if (cbor_value_is_integer(&map)) {
            int64_t ckey;
            cbor_value_get_int64(&map, &ckey);
            if (ckey == (int64_t)key) {
                cose_hdr_from_cbor_map(hdr, &map);
                return true;
            }
        }
        cbor_value_advance(&map);
        cbor_value_advance(&map);
    }
    return false;
}

bool cose_hdr_get_protected(cose_headers_t *headers, cose_hdr_t *hdr, int32_t key)
{
    bool res = false;
    if (headers->prot.c) {
        /* Unprotected header length can't be zero for cbor byte stream */
        if (headers->unprot_len) {
            res = cose_hdr_get_cbor(headers->prot.b, headers->prot_len, hdr, key);
        }
        else {
            res = cose_hdr_get_hdr(headers->prot.c, hdr, key);
        }
    }
  return res;
}

bool cose_hdr_get_unprotected(cose_headers_t *headers, cose_hdr_t *hdr, int32_t key)
{
    bool res = false;
    if (headers->unprot.c) {
        if (headers->unprot_len) {
            res = cose_hdr_get_cbor(headers->unprot.b, headers->unprot_len, hdr, key);
        }
        else {
            res = cose_hdr_get_hdr(headers->unprot.c, hdr, key);
        }
    }
    return res;
}
