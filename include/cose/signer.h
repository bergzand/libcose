/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_SIGNER_H
#define COSE_SIGNER_H

#include <stdlib.h>
#include <stdint.h>
#include "cose_defines.h"
#include "cose.h"
#include "cn-cbor/cn-cbor.h"

/**
 * COSE signer object
 */
typedef struct cose_signer {
    cose_kty_t kty;     /** Key type */
    cose_curve_t crv;   /** Curve, algo is derived from this */
    uint8_t *kid;       /** Key identifier */
    size_t kid_len;     /** length of the key identifier */
    uint8_t *x;         /** Public key part 1, must match the expected size of the algorithm */
    uint8_t *y;         /** Public key part 2, when not NULL, must match the expected size of the algorithm */
    uint8_t *d;         /** Private key, must match the expected size of the algorithm */
} cose_signer_t;

/**
 * cose_signer_from_cbor initializes a signer struct based on a cbor map
 *
 * @param signer    Empty signer struct to fill with signer information
 * @param cn        CBOR structure to initialize from
 */
int cose_signer_from_cbor(cose_signer_t *signer, cn_cbor *cn);

/**
 * cose_signer_set_key sets the key data of a signer
 * TODO: params
 */
void cose_signer_set_keys(cose_signer_t *signer, cose_curve_t curve,
        uint8_t* x, uint8_t* y, uint8_t* d);


void cose_signer_init(cose_signer_t *signer);
cn_cbor *cose_signer_cbor_protected(const cose_signer_t *signer, cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Set the KID value of a signer
 */
void cose_signer_set_kid(cose_signer_t *signer, uint8_t* kid, size_t kid_len);

/**
 * Serialize the protected header of a signer into the buffer
 */
size_t cose_signer_serialize_protected(const cose_signer_t *signer, uint8_t* out, size_t outlen, cn_cbor_context *ct, cn_cbor_errback *errp);

/**
 * Return the unprotected header as cn_cbor map
 */
cn_cbor *cose_signer_cbor_unprotected(const cose_signer_t *signer, cn_cbor_context *ct, cn_cbor_errback *errp);
int cose_signer_protected_to_map(const cose_signer_t *signer, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);
int cose_signer_unprotected_to_map(const cose_signer_t *signer, cn_cbor *map, cn_cbor_context *ct, cn_cbor_errback *errp);
#endif
