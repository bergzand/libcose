/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef COSE_INTERN_H
#define COSE_INTERN_H

#include <cn-cbor/cn-cbor.h>

/*
 * Internal cose functions
 */

#define CBOR_CATCH_ERR(cn_new, cn_top, ct)  if (!(cn_new)) { \
                                                cn_cbor_free(cn_top, ct); \
                                                return NULL; \
                                            } \

cose_err_t cose_intern_err_translate(cn_cbor_errback *errp);

/* Debugging convenience function */
static inline void print_bytestr(uint8_t *bytes, size_t len)
{
    for (unsigned int idx = 0; idx < len; idx++) {
        printf("%02X", bytes[idx]);
    }
}

#endif
