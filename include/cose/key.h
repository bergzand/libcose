/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_key COSE key defintions
 * @ingroup     cose
 * Internal constants for signing
 * @{
 *
 * @file
 * @brief       API definitions for COSE key objects
 *
 * @author      Koen Zandberg <koen@bergzand.net>
*/

#ifndef COSE_SIGNER_H
#define COSE_SIGNER_H

#include <stdlib.h>
#include <stdint.h>
#include "cose_defines.h"
#include "cose.h"
#include "cn-cbor/cn-cbor.h"

/**
 * @name COSE key object
 *
 * For signing, only the d parameter is required and the x and y coordinates
 * can be set to NULL. For verification the d part can be set to NULL.
 * For Eddsa, the y part is not used and must be NULL.
 *
 * @{
 */
typedef struct cose_key {
    cose_kty_t kty;     /**< Key type */
    cose_algo_t algo;   /**< Key algorithm restriction with this key */
    cose_curve_t crv;   /**< Curve, algo is derived from this for now */
    uint8_t *kid;       /**< Key identifier */
    size_t kid_len;     /**< length of the key identifier */
    uint8_t *x;         /**< Public key part 1, must match the expected size of the algorithm */
    uint8_t *y;         /**< Public key part 2, when not NULL, must match the expected size of the algorithm */
    uint8_t *d;         /**< Private key, must match the expected size of the algorithm */
} cose_key_t;
/** @} */

/**
 * Initialize a cose key object, must be called before using the key
 * object
 *
 * @param   key      Signer object to initialize
 */
void cose_key_init(cose_key_t *key);

/**
 * cose_key_from_cbor initializes a key struct based on a cbor map
 *
 * @param   key      Empty key struct to fill with key information
 * @param   cn          CBOR structure to initialize from
 *
 * @return              0 on successfully loaded from cbor
 * @return              Negative on error
 */
int cose_key_from_cbor(cose_key_t *key, cn_cbor *cn);

/**
 * cose_key_set_key sets the key data of a key
 * Parameters according to https://tools.ietf.org/html/rfc8152#section-13
 *
 * @param   key      The key to set the key data for
 * @param   curve       The curve used
 * @param   x           Pointer to the "x-coordinate" of the key
 * @param   y           Pointer to the "y-coordinate" of the key
 * @param   d           Pointer to the private part of the key
 */
void cose_key_set_keys(cose_key_t *key, cose_curve_t curve,
                          uint8_t *x, uint8_t *y, uint8_t *d);


/**
 * Set the KID value of a key
 *
 * @param   key  The key to set the key ID for
 * @param   kid     Pointer to the key ID byte string
 * @param   len     Length of the key ID
 */
void cose_key_set_kid(cose_key_t *key, uint8_t *kid, size_t len);

/**
 * Add the protected headers to the provided CBOR map
 *
 * @param   key  The key object
 * @param   map     The cbor map object to add headers to
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          0 on success
 * @return          Negative on error
 */
int cose_key_protected_to_map(const cose_key_t *key, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Add the unprotected header information to the provided CBOR map
 *
 * @param   key  The key object
 * @param   map     The cbor map object to add headers to
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   errp    error return struct from cn-cbor
 *
 * @return          0 on success
 * @return          Negative on error
 */
int cose_key_unprotected_to_map(const cose_key_t *key, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);
#endif
/** @} */
