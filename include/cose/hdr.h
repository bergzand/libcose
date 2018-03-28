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
#include "cose.h"

bool cose_hdr_to_cbor_map(cose_hdr_t *hdr, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);
bool cose_hdr_from_cbor_map(cose_hdr_t *hdr, cn_cbor *key, cn_cbor_context *ct, cn_cbor_errback *errp);
static inline bool cose_hdr_is_protected(cose_hdr_t *hdr)
{
    return (bool)(hdr->flags & COSE_HDR_FLAGS_PROTECTED);
}

#endif
