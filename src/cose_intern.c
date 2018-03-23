/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "cose.h"

cose_err_t cose_intern_err_translate(cn_cbor_errback *errp)
{
    switch(errp->err) {
        case CN_CBOR_NO_ERROR:
            return COSE_OK;
        case CN_CBOR_ERR_OUT_OF_DATA:
            return COSE_ERR_INVALID_CBOR;
        case CN_CBOR_ERR_NOT_ALL_DATA_CONSUMED:
            return COSE_ERR_INVALID_CBOR;
        case CN_CBOR_ERR_ODD_SIZE_INDEF_MAP:
            return COSE_ERR_INVALID_CBOR;
        case CN_CBOR_ERR_BREAK_OUTSIDE_INDEF:
            return COSE_ERR_INVALID_CBOR;
        case CN_CBOR_ERR_MT_UNDEF_FOR_INDEF:
            return COSE_ERR_INVALID_CBOR;
        case CN_CBOR_ERR_RESERVED_AI:
        case CN_CBOR_ERR_WRONG_NESTING_IN_INDEF_STRING:
            return COSE_ERR_INVALID_CBOR;
        case CN_CBOR_ERR_INVALID_PARAMETER:
            return COSE_ERR_INVALID_PARAM;
        case CN_CBOR_ERR_OUT_OF_MEMORY:
            return COSE_ERR_NOMEM;
        case CN_CBOR_ERR_FLOAT_NOT_SUPPORTED:
            return COSE_ERR_CBOR_NOTSUP;
    }
    return COSE_OK;
}
