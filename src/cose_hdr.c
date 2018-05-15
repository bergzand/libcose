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

int cose_hdr_add_from_cbor(cose_hdr_t *hdr, size_t num, const CborValue *map,
        uint8_t flags)
{
    CborValue val;
    cbor_value_enter_container(map, &val);
    unsigned idx = 0;
    while (!cbor_value_at_end(&val)) {
        for (; hdr->key != 0; hdr++, idx++) {
            if (idx >= num) {
                return COSE_ERR_NOMEM;
            }
        }
        if (!cose_hdr_from_cbor_map(hdr, &val)) {
            return COSE_ERR_INVALID_CBOR;
        }
        hdr->flags |= flags;
        hdr++;
        idx++;
        /* Advance twice */
        cbor_value_advance(&val);
        cbor_value_advance(&val);
    }
    return COSE_OK;
}

int cose_hdr_add_hdr_value(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, int32_t value)
{
    cose_hdr_t *hdr = cose_hdr_next_empty(start, num);

    if (!hdr) {
        return COSE_ERR_NOMEM;
    }
    hdr->type = COSE_HDR_TYPE_INT;
    hdr->key = key;
    hdr->v.value = value;
    hdr->flags = flags;
    return COSE_OK;
}

int cose_hdr_add_hdr_string(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, const char *str)
{
    cose_hdr_t *hdr = cose_hdr_next_empty(start, num);

    if (!hdr) {
        return COSE_ERR_NOMEM;
    }
    hdr->type = COSE_HDR_TYPE_TSTR;
    hdr->key = key;
    hdr->v.str = str;
    hdr->flags = flags;
    return COSE_OK;
}

int cose_hdr_add_hdr_data(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, const uint8_t *data, size_t len)
{
    cose_hdr_t *hdr = cose_hdr_next_empty(start, num);

    if (!hdr) {
        return COSE_ERR_NOMEM;
    }
    hdr->type = COSE_HDR_TYPE_BSTR;
    hdr->key = key;
    hdr->v.data = data;
    hdr->len = len;
    hdr->flags = flags;
    return COSE_OK;
}

cose_hdr_t *cose_hdr_next_empty(cose_hdr_t *hdr, size_t num)
{
    cose_hdr_t *res = NULL;

    for (unsigned i = 0; i < num; i++, hdr++) {
        if (hdr->key == 0) {
            res = hdr;
            break;
        }
    }
    return res;
}

CborError cose_hdr_add_to_map(const cose_hdr_t *hdr, size_t num, CborEncoder *map, bool prot)
{
    CborError err = 0;
    for (unsigned i = 0; i < num; i++, hdr++) {
        if (hdr->key == 0 || (cose_hdr_is_protected(hdr) != prot) ) {
            continue;
        }
        err = cose_hdr_to_cbor_map(hdr, map);
    }
    return err;
}

size_t cose_hdr_size(const cose_hdr_t *hdr, size_t num, bool prot)
{
    size_t res = 0;
    for (unsigned i = 0; i < num; i++, hdr++) {
        if (hdr->key != 0 && (cose_hdr_is_protected(hdr) == prot)) {
            res++;
        }
    }
    return res;
}
