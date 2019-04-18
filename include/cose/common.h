/*
 * Copyright (C) 2019 Koen Zandberg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_COMMON_H
#define COSE_COMMON_H

#include <nanocbor/nanocbor.h>

#include "cose/conf.h"

#ifdef __cplusplus
extern "C" {
#endif

int cose_cbor_decode_get_pos(const uint8_t *start, size_t len,
                             nanocbor_value_t *arr,
                             unsigned idx);

int cose_cbor_decode_get_prot(const uint8_t *start, size_t len,
                              const uint8_t **prot, size_t *prot_len);

int cose_cbor_decode_get_unprot(const uint8_t *start, size_t len,
                                const uint8_t **unprot, size_t *unprot_len);

#ifdef __cplusplus
}
#endif

#endif

/** @} */
