/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_hdr COSE header manipulation definitions
 * @ingroup     cose
 *
 * COSE protected and unprotected header manipulation functions
 * @{
 *
 * @file
 * @brief       API definitions for COSE header manipulation
 *
 * @author      Koen Zandberg <koen@bergzand.net>
*/
#ifndef COSE_HDR_H
#define COSE_HDR_H

#include "cose_defines.h"
#include <cn-cbor/cn-cbor.h>
#include <stdbool.h>

/**
 * @name COSE header struct
 *
 * Generic COSE key value header struct. The flags select the protected or unprotected
 * buffer.
 *
 * @{
 */
typedef struct cose_hdr {
    int32_t key;                /**< Header label */
    cose_hdr_type_t type;       /**< Type of the header */
    uint8_t flags;              /**< Flags for the header */
    size_t len;                 /**< Length of the data, only used for the bytes type */
    union {                     /**< Depending on the type, the content is a pointer or an integer */
        int32_t value;          /**< Direct integer value */
        const uint8_t *data;    /**< Pointer to the content */
        const char *str;        /**< String type content */
        cn_cbor *cbor;          /**< cbor type data */
    } v;                        /**< Union to combine different value types */
} cose_hdr_t;
/** @} */

/**
 * Convert a COSE header struct to a CBOR representation and add it to the map
 *
 * @param   hdr     Header struct to convert
 * @param   map     Map to add the header to
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          True when succeeded
 */
bool cose_hdr_to_cbor_map(const cose_hdr_t *hdr, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Convert a cn_cbor struct to a COSE header struct.
 *
 * The key is expected to have a valid next pointer to the value
 *
 * @param   hdr     Header struct to convert
 * @param   key     The cn-cbor key to convert.
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          True when succeeded
 */
bool cose_hdr_from_cbor_map(cose_hdr_t *hdr, cn_cbor *key, cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Add a header with an integer based value to the set of headers
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   start       The first header in the array
 * @param   num         The number of headers in the array
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   value       The value to set in the header
 *
 * @return              0 on success
 * @return              Negative when failed
 */
int cose_hdr_add_hdr_value(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, int32_t value);

/**
 * Add a header with a string based value to the set of headers
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   start       The first header in the array
 * @param   num         The number of headers in the array
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   str         zero terminated string to set
 *
 * @return              0 on success
 * @return              Negative when failed
 */
int cose_hdr_add_hdr_string(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, const char *str);

/**
 * Add a header with a byte array based value to the set of headers
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   start       The first header in the array
 * @param   num         The number of headers in the array
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   data        The byte array to add
 * @param   len         Length of the byte array
 *
 * @return              0 on success
 * @return              Negative when failed
 */
int cose_hdr_add_hdr_data(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, const uint8_t *data, size_t len);

/**
 * Add a header with a CBOR based value to the set of headers
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   start       The first header in the array
 * @param   num         The number of headers in the array
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   cbor        The cbor struct to set
 *
 * @return              0 on success
 * @return              Negative when failed
 */
int cose_hdr_add_hdr_cbor(cose_hdr_t *start, size_t num, int32_t key, uint8_t flags, cn_cbor *cbor);

/**
 * Retrieve the next empty header in a set of headers
 *
 * @param   hdr         The first header in the array
 * @param   num         The number of headers in the array
 *
 * @return              The header
 * @return              NULL when no headers are empty
 */
cose_hdr_t *cose_hdr_next_empty(cose_hdr_t *hdr, size_t num);

/**
 * Convert a cbor header representation to cose_hdr_t structs
 *
 * @param   hdr     Header struct array to fill
 * @param   num     Number of headers in the array
 * @param   map     Map to get the headers from
 * @param   flags   Additional flags to set for these headers
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          True when succeeded
 */
int cose_hdr_add_from_cbor(cose_hdr_t *hdr, size_t num, cn_cbor *map, uint8_t flags,
                           cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Iterate over the headers and add them to a supplied cbor map
 *
 * @param   hdr     Header struct array to feed from
 * @param   num     Number of headers in the array
 * @param   map     Map to add headers to
 * @param   prot    True adds only protected, false only unprotected
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          True when succeeded
 */
bool cose_hdr_add_to_map(const cose_hdr_t *hdr, size_t num, cn_cbor *map, bool prot, cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Convert a cbor unprotected header representation to cose_hdr_t structs
 *
 * @param   hdr     Header struct array to fill
 * @param   num     Number of headers in the array
 * @param   map     Map to get the headers from
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          0 on success
 * @return          Negative otherwise
 */
static inline int cose_hdr_add_unprot_from_cbor(cose_hdr_t *hdr, size_t num, cn_cbor *map,
                                                cn_cbor_context *ct, cn_cbor_errback *errp)
{
    return cose_hdr_add_from_cbor(hdr, num, map, 0, ct, errp);
}

/**
 * Convert a cbor protected header representation to cose_hdr_t structs
 *
 * @param   hdr     Header struct array to fill
 * @param   num     Number of headers in the array
 * @param   buf     Serialized buffer to read from
 * @param   len     Length of the buffer
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          0 on success
 * @return          Negative otherwise
 */
static inline int cose_hdr_add_prot_from_cbor(cose_hdr_t *hdr, size_t num, const uint8_t *buf, size_t len,
                                              cn_cbor_context *ct, cn_cbor_errback *errp)
{
    ssize_t res = 0;
    cn_cbor *cn_prot = cn_cbor_decode(buf, len, ct, errp);

    if (cn_prot && cn_prot->type == CN_CBOR_MAP) {
        cose_hdr_add_from_cbor(hdr, num, cn_prot, COSE_HDR_FLAGS_PROTECTED, ct, errp);
    }
    cn_cbor_free(cn_prot, ct);
    return res;
}

/**
 * Check if a headers is in the protected bucket
 *
 * @param   hdr     Header to check
 *
 * @return          True when it is in the protected buffer
 * @return          False otherwise
 */
static inline bool cose_hdr_is_protected(const cose_hdr_t *hdr)
{
    return (bool)(hdr->flags & COSE_HDR_FLAGS_PROTECTED);
}

/**
 * Retrieve a header from either the protected or the unprotected bucket by key
 *
 * @param   hdr     Header array to search
 * @param   num     Size of the header array
 * @param   key     Key to look for
 * @param   protect True when to search the protected headers
 *
 * @return          Header struct with matching key
 * @return          NULL when no header has been found
 */
static inline cose_hdr_t *cose_hdr_get_bucket(cose_hdr_t *hdr, size_t num, int32_t key, bool protect)
{
    for (unsigned i = 0; i < num; hdr++, i++) {
        if (hdr->key == key && cose_hdr_is_protected(hdr) == protect) {
            return hdr;
        }
    }
    return NULL;
}

/**
 * Retrieve a header by key
 *
 * @param   hdr     Header array to search
 * @param   num     Size of the header array
 * @param   key     Key to look for
 *
 * @return          Header struct with matching key
 * @return          NULL when no header has been found
 */
static inline cose_hdr_t *cose_hdr_get(cose_hdr_t *hdr, size_t num, int32_t key)
{
    for (unsigned i = 0; i < num; hdr++, i++) {
        if (hdr->key == key) {
            return hdr;
        }
    }
    return NULL;
}

#endif

/** @} */
