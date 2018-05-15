/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose_defines.h"
#include <cbor.h>
#include <string.h>

int cose_cbor_get_string(const CborValue *it, const uint8_t **buf, size_t *len)
{
    if (!(cbor_value_is_text_string(it) || cbor_value_is_byte_string(it) || cbor_value_is_length_known(it))) {
         return COSE_ERR_INVALID_CBOR;
    }
    CborValue next = *it;
    cbor_value_get_string_length(it, len);
    cbor_value_advance(&next);
    *buf = next.ptr - *len;
    return COSE_OK;
}
