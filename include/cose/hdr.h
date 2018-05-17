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
#include <cbor.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @name COSE header struct
 *
 * Generic COSE key value header struct. The flags select the protected or
 * unprotected bucket.
 *
 * @{
 */
typedef struct cose_hdr {
    struct cose_hdr *next;/**< Next header in list */
    int32_t key;                /**< Header label */
    size_t len;                 /**< Length of the data, only used for the byte type */
    union {                     /**< Depending on the type, the content is a pointer or an integer */
        int32_t value;          /**< Direct integer value */
        const uint8_t *data;    /**< Pointer to the content */
        const char *str;        /**< String type content */
    } v;                        /**< Union to combine different value types */
    cose_hdr_type_t type;       /**< Type of the header */
} cose_hdr_t;
/** @} */

/**
 * @name COSE header pack
 *
 * Struct packing both header buckets
 */
typedef struct {
    union {
        cose_hdr_t *c;
        const uint8_t *b;
    } prot;
    union {
        cose_hdr_t *c;
        const uint8_t *b;
    } unprot;
    size_t prot_len;
    size_t unprot_len;
} cose_headers_t;
/** @} */

/**
 * Convert a COSE header struct to a CBOR representation and add it to the map
 *
 * @param   hdr     Header struct to convert
 * @param   map     Map encoder to add the header to
 *
 * @return          0 on success
 */
CborError cose_hdr_to_cbor_map(const cose_hdr_t *hdr, CborEncoder *map);

/**
 * Convert a cbor stream to a COSE header struct.
 *
 * The key is expected to have a valid next pointer to the value
 *
 * @param   hdr     Header struct to convert
 * @param   key     The cn-cbor key to convert.
 *
 * @return          True when succeeded
 */
bool cose_hdr_from_cbor_map(cose_hdr_t *hdr, const CborValue *key);

/**
 * Format header with an integer based value
 *
 * @param   hdr         The header to modify
 * @param   key         The key to add
 * @param   value       The value to set in the header
 */
void cose_hdr_format_int(cose_hdr_t *hdr, int32_t key, int32_t value);

/**
 * Format header with a string based value
 *
 * @param   hdr         The header to modify
 * @param   key         The key to add
 * @param   str         zero terminated string to set
 */
void cose_hdr_format_string(cose_hdr_t *hdr, int32_t key, const char *str);

/**
 * Format header with a byte array based value
 *
 * @param   hdr         The header to modify
 * @param   key         The key to add
 * @param   data        The byte array to add
 * @param   len         Length of the byte array
 */
void cose_hdr_format_data(cose_hdr_t *hdr, int32_t key, const uint8_t *data,
        size_t len);

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
 *
 * @return          True when succeeded
 */
int cose_hdr_add_from_cbor(cose_hdr_t *hdr, size_t num, const CborValue *map);

/**
 * Iterate over the headers and add them to a supplied cbor map
 *
 * @param   hdr     Header struct array to feed from
 * @param   map     CborEncoder map
 *
 * @return          0 on success
 */
CborError cose_hdr_add_to_map(const cose_hdr_t *hdr, CborEncoder *map);

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
static inline int cose_hdr_add_unprot_from_cbor(cose_hdr_t *hdr, size_t num,
        CborValue *map)
{
    return cose_hdr_add_from_cbor(hdr, num, map);
}

size_t cose_hdr_size(const cose_hdr_t *hdr);
void cose_hdr_insert(cose_hdr_t **hdrs, cose_hdr_t *nhdr);

/**
 * Convert a cbor protected header representation to cose_hdr_t structs
 *
 * @param   hdr     Header struct array to fill
 * @param   num     Number of headers in the array
 * @param   buf     Serialized buffer to read from
 * @param   len     Length of the buffer
 *
 * @return          0 on success
 * @return          Negative otherwise
 */
static inline int cose_hdr_add_prot_from_cbor(cose_hdr_t *hdr, size_t num,
        const uint8_t *buf, size_t len)
{
    int res = 0;
    CborParser p;
    CborValue it;
    cbor_parser_init(buf, len, 0, &p, &it);
    if (cbor_value_is_map(&it)) {
        res = cose_hdr_add_from_cbor(hdr, num, &it);
    }
    return res;
}

bool cose_hdr_get_protected(cose_headers_t *headers, cose_hdr_t *hdr, int32_t key);
bool cose_hdr_get_unprotected(cose_headers_t *headers, cose_hdr_t *hdr, int32_t key);

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
static inline bool cose_hdr_get(cose_headers_t *headers, cose_hdr_t *hdr,
        int32_t key)
{
    if (cose_hdr_get_protected(headers, hdr, key) ||
            cose_hdr_get_unprotected(headers, hdr, key)) {
        return true;
    }
    return false;
}

#endif

/** @} */
