/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cbor COSE CBOR auxiliary functions
 * @ingroup     cose
 * @{
 *
 * @file
 * @brief       Extra cbor related functions
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */
#ifndef COSE_CBOR_H
#define COSE_CBOR_H

#include <cbor.h>

#ifdef __cplusplus
extern "C" {
#endif

int cose_cbor_get_string(const CborValue *it, const uint8_t **buf, size_t *len);

#ifdef __cplusplus
}
#endif

#endif

/** @} */
