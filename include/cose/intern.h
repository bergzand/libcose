/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef COSE_INTERN_H
#define COSE_INTERN_H

#include <stdio.h>
#include <cn-cbor/cn-cbor.h>

/**
 * @defgroup    cose_internal COSE internal convenience functions
 * @ingroup     cose
 * Internal convenience functions
 * @{
 *
 * @file
 * @brief       Internal convenience functions
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

/**
 * @brief Check the cn_new struct for a valid value,
 * free the cn_top cbor struct and return NULL.
 */
#define CBOR_CATCH_ERR(cn_new, cn_top, ct)  if (!(cn_new)) { \
        cn_cbor_free(cn_top, ct); \
        return NULL; \
} \

/**
 * @brief Check the cn_new struct for a valid value,
 * free the cn_top cbor struct and return the error.
 */
#define CBOR_CATCH_RET_ERR(cn_new, cn_top, ct, errp) \
    if (!(cn_new)) { \
        cn_cbor_free(cn_top, ct); \
        return cose_intern_err_translate(errp); \
    } \

/**
 * Translate a cn-cbor error to a COSE error
 *
 * @param   errp   cn-cbor error
 *
 * @return          COSE error
 */
cose_err_t cose_intern_err_translate(cn_cbor_errback *errp);

/**
 * Debugging convenience function for printing byte strings as hex
 *
 * @param   bytes   Byte array to print
 * @param   len     Length of the byte array
 */
static inline void print_bytestr(const uint8_t *bytes, size_t len)
{
    for (unsigned int idx = 0; idx < len; idx++) {
        printf("%02X", bytes[idx]);
    }
}

/**
 * Check if a specific flag is set
 *
 * @param   flags       Flags to check
 * @param   flag        Flag to check for
 *
 * @return              True when the flag is set
 */
static inline bool cose_flag_isset(uint16_t flags, uint16_t flag)
{
    return flags & flag;
}

#endif

/** @} */
