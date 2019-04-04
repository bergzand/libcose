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

cose_err_t cose_intern_err_translate(CborError err)
{
    if (err == CborNoError) {
        return COSE_OK;
    }
    return COSE_ERR_INVALID_CBOR;
}
