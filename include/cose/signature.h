/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_signature COSE signature defintions
 * @ingroup     cose
 * @{
 *
 * @file
 * @brief       API definitions for COSE signatures
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_SIGNATURE_H
#define COSE_SIGNATURE_H

#include "cose/common.h"
#include "cose/conf.h"
#include "cose/hdr.h"
#include "cose/key.h"
#include <nanocbor/nanocbor.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Signature struct
 * @brief Contains signature and headers related to the signatures
 * @{
 */
typedef struct cose_signature {
    struct cose_signature *next;    /**< Next signature in list */
    cose_headers_t hdrs;            /**< Headers */
    const uint8_t *signature;       /**< Pointer to the signature */
    size_t signature_len;           /**< Length of the signature */
    const cose_key_t *signer;       /**< Pointer to the signer used for this signature */
} cose_signature_t;
/** @} */

/**
 * @name Signature decoder struct
 * @brief Contains the buffer information required for decoding a signature
 * @{
 */
typedef struct cose_signature_dec {
    const uint8_t *buf;     /**< Buffer containing the full signature data */
    size_t len;             /**< Length of the signature data */
} cose_signature_dec_t;
/** @} */

/**
 * @brief Initialize a cose signature struct
 *
 * @param   signature   Signature encoder struct to initialize
 */
static inline void cose_signature_init(cose_signature_t *signature)
{
    memset(signature, 0, sizeof(cose_signature_t));
}

/**
 * @brief Serialize the protected headers of a signature struct
 *
 * @param   sig     Encoder signature struct
 * @param   encode
 * @param   buf     Buffer to encode into
 * @param   buflen  length of the buffer
 */
size_t cose_signature_serialize_protected(const cose_signature_t *sig,
                                          bool encode, uint8_t *buf,
                                          size_t buflen);

bool cose_signature_unprot_to_map(cose_signature_t *sig,
 nanocbor_encoder_t *map);

int cose_signature_unprot_cbor(cose_signature_t *sig,
        nanocbor_encoder_t *enc);

/**
 * @brief Retrieve a header from a signature object by key lookup
 *
 * @param   signature   The signature object to operate on
 * @param   hdr         hdr struct to fill
 * @param   key         The key to look up
 *
 * @return              A header object with matching key
 * @return              NULL if there is no header with the key
 */
bool cose_signature_get_header(cose_signature_t *signature, cose_hdr_t *hdr, int32_t key);

/**
 * @brief Retrieve a protected header from a signature object by key lookup
 *
 * @param   signature   The signature object to operate on
 * @param   hdr         hdr struct to fill
 * @param   key         The key to look up
 *
 * @return              A protected header object with matching key
 * @return              NULL if there is no header with the key
 */
bool cose_signature_get_protected(cose_signature_t *signature, cose_hdr_t *hdr, int32_t key);

/**
 * @brief Retrieve an unprotected header from a signature object by key lookup
 *
 * @param   signature   The signature object to operate on
 * @param   hdr         hdr struct to fill
 * @param   key         The key to look up
 *
 * @return              A protected header object with matching key
 * @return              NULL if there is no header with the key
 */
bool cose_signature_get_unprotected(cose_signature_t *signature, cose_hdr_t *hdr, int32_t key);

size_t cose_signature_num(cose_signature_t *signature);

/**
 * @brief Initialize a signature decoder context
 *
 * @param   signature   The signature decoder
 * @param   buf         Buffer to read signature data from
 * @param   len         length of the buffer
 */
void cose_signature_decode_init(cose_signature_dec_t *signature, const uint8_t *buf, size_t len);

static inline bool cose_signature_decode_protected_buf(const cose_signature_dec_t *signature, const uint8_t **buf, size_t *len)
{
    return cose_cbor_decode_get_prot(signature->buf, signature->len, buf, len);
}

/**
 * Retrieve a protected header from a signature object by key lookup
 *
 * @param       signature   The signature decode object to operate on
 * @param[out]  hdr         Header to fill with the values
 * @param       key         The key to look up
 *
 * @return                  COSE_OK if a header is found
 * @return                  COSE_ERR_NOT_FOUND if no header with matching key
 *                          is found
 */
int cose_signature_decode_protected(const cose_signature_dec_t *signature,
                                    cose_hdr_t *hdr, int32_t key);

/**
 * Retrieve an unprotected header from a signature object by key lookup
 *
 * @param       signature   The signature decode object to operate on
 * @param[out]  hdr         Header to fill with the values
 * @param       key         The key to look up
 *
 * @return                  COSE_OK if a header is found
 * @return                  COSE_ERR_NOT_FOUND if no header with matching key
 *                          is found
 */
int cose_signature_decode_unprotected(const cose_signature_dec_t *signature,
                                      cose_hdr_t *hdr, int32_t key);

/**
 * @brief Decode a cryptographic signature from the signature decoder object
 *
 * @param   signature   Signature decode context
 * @param   sign        pointer to the signature buffer
 * @param   len         length of the signature
 *
 * @return                  COSE_OK if a signature is retrieved
 * @return                  Negative on error
 */
int cose_signature_decode_signature(const cose_signature_dec_t *signature, const uint8_t **sign, size_t *len);

/**
 * Get the key ID from a signature
 *
 * @param      signature    Signature decode context
 * @param[out] kid          Pointer to the key ID
 *
 * @return                  Size of the key ID
 * @return                  0 in case of no key ID
 */
COSE_ssize_t cose_signature_decode_kid(const cose_signature_dec_t *signature, const uint8_t **kid);

/**
 * Add a header to a signatures protected bucket
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   signature   The signature object to operate on
 * @param   hdr         The header to add
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline void cose_signature_insert_prot(cose_signature_t *signature,
        cose_hdr_t *hdr)
{
    cose_hdr_insert(&signature->hdrs.prot, hdr);
}

/**
 * Add a header to a signatures unprotected bucket
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   signature   The signature object to operate on
 * @param   hdr         The header to add
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline void cose_signature_insert_unprot(cose_signature_t *signature,
        cose_hdr_t *hdr)
{
    cose_hdr_insert(&signature->hdrs.unprot, hdr);
}

#ifdef __cplusplus
}
#endif

#endif
