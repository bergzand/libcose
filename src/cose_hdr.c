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
#include <cn-cbor/cn-cbor.h>

/* Appends the header the given cbor map */
bool cose_hdr_to_cbor_map(cose_hdr_t *hdr, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *value = NULL;

    switch (hdr->type) {
        case COSE_HDR_TYPE_INT:
            value = cn_cbor_int_create(hdr->v.value, ct, errp);
            break;
        case COSE_HDR_TYPE_TSTR:
            value = cn_cbor_string_create(hdr->v.str, ct, errp);
            break;
        case COSE_HDR_TYPE_BSTR:
            value = cn_cbor_data_create(hdr->v.data, hdr->len, ct, errp);
            break;
        case COSE_HDR_TYPE_CBOR:
            value = hdr->v.cbor;
            break;
    }
    if (!value) {
        return false;
    }
    if (!(cn_cbor_mapput_int(map, hdr->key, value, ct, errp))) {
        /* Error handling */
        if (hdr->type != COSE_HDR_TYPE_CBOR) {
            cn_cbor_free(value, ct);
        }
        return false;
    }
    return true;
}

/* Convert a map key to a cose_hdr struct */
bool cose_hdr_from_cbor_map(cose_hdr_t *hdr, cn_cbor *key, cn_cbor_context *ct, cn_cbor_errback *errp)
{
    (void)ct;
    (void)errp;
    if (key->type == CN_CBOR_INT) {
        hdr->key = (int32_t)key->v.sint;
    }
    else if (key->type == CN_CBOR_UINT) {
        hdr->key = (int32_t)key->v.uint;
    }
    else {
        return false;
    }
    cn_cbor *val = key->next;
    switch (val->type) {
        case CN_CBOR_UINT:
            hdr->v.value = (int32_t)val->v.uint;
            hdr->type = COSE_HDR_TYPE_INT;
            break;
        case CN_CBOR_INT:
            hdr->v.value = (int32_t)val->v.sint;
            hdr->type = COSE_HDR_TYPE_INT;
            break;
        case CN_CBOR_TEXT:
            hdr->v.str = val->v.str;
            hdr->type = COSE_HDR_TYPE_TSTR;
            break;
        case CN_CBOR_BYTES:
            hdr->v.data = val->v.bytes;
            hdr->len = val->length;
            hdr->type = COSE_HDR_TYPE_BSTR;
            break;
        case CN_CBOR_ARRAY:
        case CN_CBOR_MAP:
        case CN_CBOR_TAG:
            /* Todo: copy map */
            hdr->v.cbor = val;
            hdr->type = COSE_HDR_TYPE_CBOR;
            break;
        default:
            return false;
    }
    return true;
}

int cose_hdr_add_from_cbor(cose_hdr_t *hdr, size_t num, cn_cbor *map, uint8_t flags,
                           cn_cbor_context *ct, cn_cbor_errback *errp)
{
    cn_cbor *cp = NULL;
    unsigned idx = 0;

    for (cp = map->first_child; cp && cp->next && idx < num; cp = cp->next->next) {
        for (; hdr->key != 0; hdr++, idx++) {
            if (idx >= num) {
                return COSE_ERR_NOMEM;
            }
        }
        if (!(cose_hdr_from_cbor_map(hdr, cp, ct, errp))) {
            /* Error handling */
        }
        hdr->flags |= flags;
        hdr++;
        idx++;
    }
    return 0;
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

int cose_hdr_add_hdr_cbor(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, cn_cbor *cbor)
{
    cose_hdr_t *hdr = cose_hdr_next_empty(start, num);

    if (!hdr) {
        return COSE_ERR_NOMEM;
    }
    hdr->type = COSE_HDR_TYPE_CBOR;
    hdr->key = key;
    hdr->v.cbor = cbor;
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
