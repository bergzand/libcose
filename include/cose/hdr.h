/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_HDR_H
#define COSE_HDR_H

#include <cn-cbor/cn-cbor.h>
#include "cose_defines.h"

typedef struct cose_hdr {
    int32_t key;                /* Header label */
    cose_hdr_type_t type;       /* Type of the header */
    uint8_t flags;              /* Flags for the header */
    size_t len;                 /* Length of the data, only used for the bytes type */
    union {                     /* Depending on the type, the content is a pointer or an integer */
        int32_t value;            /* Direct integer value */
        const uint8_t *data;          /* Pointer to the content */
        const char *str;              /* String type content */
        cn_cbor *cbor;          /* cbor type data */
    } v;
} cose_hdr_t;

bool cose_hdr_to_cbor_map(cose_hdr_t *hdr, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);
bool cose_hdr_from_cbor_map(cose_hdr_t *hdr, cn_cbor *key, cn_cbor_context *ct, cn_cbor_errback *errp);

int cose_hdr_add_hdr_value(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, int32_t value);
int cose_hdr_add_hdr_string(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, char *str);
int cose_hdr_add_hdr_data(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, uint8_t *data, size_t len);
int cose_hdr_add_hdr_cbor(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, cn_cbor *cbor);
cose_hdr_t *cose_hdr_next_empty(cose_hdr_t *hdr, size_t  num);

int cose_hdr_add_from_cbor(cose_hdr_t *hdr, size_t num, cn_cbor *map, uint8_t flags,
        cn_cbor_context *ct, cn_cbor_errback *errp);

static inline int cose_hdr_add_unprot_from_cbor(cose_hdr_t *hdr, size_t num, cn_cbor *map,
        cn_cbor_context *ct, cn_cbor_errback *errp)
{
    return cose_hdr_add_from_cbor(hdr, num, map, 0, ct, errp);
}

static inline int cose_hdr_add_prot_from_cbor(cose_hdr_t *hdr, size_t num, const uint8_t *buf, size_t buflen,
        cn_cbor_context *ct, cn_cbor_errback *errp)
{
    ssize_t res = 0;
    cn_cbor *cn_prot = cn_cbor_decode(buf, buflen, ct, errp);
    if (cn_prot && cn_prot->type == CN_CBOR_MAP) {
        cose_hdr_add_from_cbor(hdr, num, cn_prot, COSE_HDR_FLAGS_PROTECTED, ct, errp);
    }
    cn_cbor_free(cn_prot, ct);
    return res;
}

static inline bool cose_hdr_is_protected(cose_hdr_t *hdr)
{
    return (bool)(hdr->flags & COSE_HDR_FLAGS_PROTECTED);
}

static inline cose_hdr_t * cose_hdr_get_flagged(cose_hdr_t *hdr, size_t num, int32_t key, bool protect)
{
    for (unsigned i = 0; i < num; hdr++, i++) {
        if (hdr->key == key && cose_hdr_is_protected(hdr) == protect) {
            return hdr;
        }
    }
    return NULL;
}

static inline cose_hdr_t * cose_hdr_get(cose_hdr_t *hdr, size_t num, int32_t key)
{
    for (unsigned i = 0; i < num; hdr++, i++) {
        if (hdr->key == key) {
            return hdr;
        }
    }
    return NULL;
}

#endif
