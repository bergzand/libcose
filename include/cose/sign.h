/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_sign COSE signing defintions
 * @ingroup     cose
 * @{
 *
 * @file
 * @brief       API definitions for COSE signing objects
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 *
 * The functions provided here allow for encoding and decoding COSE sign and
 * COSE sign1 structures.
 */

#ifndef COSE_SIGN_H
#define COSE_SIGN_H

#include "cose/conf.h"
#include "cose/hdr.h"
#include "cose/key.h"
#include "cose/signature.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name COSE sign,
 * https://tools.ietf.org/html/rfc8152#section-4
 *
 * @brief Struct for conversion to both the COSE sign1 and COSE sign objects.
 * @{
 */
typedef struct cose_sign {
    cose_headers_t hdrs;            /**< Headers */
    cose_signature_t *signatures;   /**< Signer data array */
    const void *payload;            /**< Pointer to the payload */
    size_t payload_len;             /**< Size of the payload */
    uint8_t *ext_aad;               /**< Pointer to the additional authenticated data */
    size_t ext_aad_len;             /**< Size of the AAD */
    const uint8_t *sig;
    size_t sig_len;
    uint16_t flags;                 /**< Flags as defined */
} cose_sign_t;
/** @} */

typedef struct cose_sign_iter {
    cose_sign_t *sign;
    nanocbor_value_t it;
    nanocbor_value_t arr;
} cose_sign_iter_t;

/**
 * @brief String constant used for signing COSE signature objects
 */
static const char SIG_TYPE_SIGNATURE[] = "Signature";

/**
 * @brief String constant used for signing COSE signature1 objects
 */
static const char SIG_TYPE_SIGNATURE1[] = "Signature1";

/**
 * @brief String constant used for signing COSE countersignatures
 */
static const char SIG_TYPE_COUNTERSIGNATURE[] = "CounterSignature";

/**
 * @name Size of the signature classes without zero terminator
 *
 * @{
 */
#define COSE_SIGN_STR_SIGNATURE_LEN         (sizeof(signature) - 1)
#define COSE_SIGN_STR_SIGNATURE1_LEN        (sizeof(signature1) - 1)
#define COSE_SIGN_STR_COUNTERSIGNATURE_LEN  (sizeof(countersignature) - 1)
/** @} */

/**
 * cose_sign_init initializes a sign struct
 *
 * @param sign     Empty sign struct to fill
 * @param flags    Flags to set for the sign object
 */
void cose_sign_init(cose_sign_t *sign, uint16_t flags);

/**
 * cose_sign_set_payload sets the payload pointer of the COSE sign struct
 *
 * @param sign      Sign struct to set the payload for
 * @param payload   The payload to set
 * @param len       The length of the payload in bytes
 */
void cose_sign_set_payload(cose_sign_t *sign, const void *payload, size_t len);

/**
 * cose_sign_get_payload retrieves the pointer and length of the payload from
 * the COSE sign struct
 *
 * @param sign      Sign struct to retrieve the payload from
 * @param payload   The pointer to the payload
 * @param len       The length of the payload in bytes
 */
void cose_sign_get_payload(cose_sign_t *sign, const uint8_t **payload,
                           size_t *len);

/**
 * cose_sign_set_external_aad adds a reference to the external data that
 * should be authenticated.
 *
 * @param   sign    The sign object
 * @param   ext     aditional authenticated data
 * @param   len     Lenght of the aad
 */
void cose_sign_set_external_aad(cose_sign_t *sign, void *ext, size_t len);

/**
 * cose_sign_add_signer adds a key to the sign struct to sign with
 *
 * @param sign      Sign struct to operate on
 * @param signer    Signature struct to add to the sign
 * @param key       The key to sign with
 *
 * @return          The index of the allocated sig on success
 * @return          negative on failure
 */
void cose_sign_add_signer(cose_sign_t *sign, cose_signature_t *signer, const cose_key_t *key);

/**
 * cose_sign_sign signs the data from the sign object with the attached
 * signers. The output is placed in the supplied buffer, starting at the
 * position indicated by the out parameter.
 *
 * This function uses the buffer as scratch space to first calculate all the
 * signatures. Therefor this buffer should be large enough to contain the
 * headers, the payload, the additionally authenticated data and the
 * signatures at the same time. This is a limitation caused by how the COSE
 * signatures to be generated and how crypto libraries require their message
 * as one continuous block of data.
 *
 * @param       sign    Sign struct to encode
 * @param       buf     Buffer to write in
 * @param[out]  out     Pointer to where the COSE sign struct starts
 * @param       len     Size of the buffer to write in
 *
 * @return          The number of bytes written
 * @return          Negative on error
 */
COSE_ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t len, uint8_t **out);

/**
 * cose_sign_decode parses a buffer to a cose sign struct. This buffer can
 * contain both a tagged sign cbor byte string or an untagged byte string
 *
 * @param   sign    Sign struct to fill
 * @param   buf     The buffer to read
 * @param   len     Length of the buffer
 *
 * @return          0 on success
 * @return          negative on failure
 */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len);

/**
 * cose_sign_iter_init initializes the iteration structure
 *
 * This must be called first before iterating over the signatures
 *
 * @param   sign        The sign object to decode from
 * @param   iter        The iteration context
 */
void cose_sign_iter_init(cose_sign_t *sign, cose_sign_iter_t *iter);

/**
 * cose_sign_iter fills the provided @p signature struct with the contents of
 * the COSE signatures from the associated sign structure.
 *
 * @param   iter        The iteration context
 * @param   signature   The signature struct to fill
 *
 * @return              true when the signature struct is filled
 * @return              false when there are no more signatures
 */
bool cose_sign_iter(cose_sign_iter_t *iter, cose_signature_t *signature);

/**
 * Verify the signature of the signed data with the supplied signature object
 *
 * The buffer is required as scratch space to build the signature structs in.
 * The buffer must be large enough to contain the headers, payload and the
 * additional authenticated data.
 *
 * @param   sign        The sign object to verify
 * @param   signature   A signature object belonging to the sign object
 * @param   key         The key to verify with
 * @param   buf         Buffer to write in
 * @param   len         Size of the buffer to write in
 *
 * @return              0 on verification success
 * @return              Negative on error
 */
int cose_sign_verify(cose_sign_t *sign, cose_signature_t *signature, cose_key_t *key, uint8_t *buf, size_t len);

/**
 * Wrapper function to attempt signature verification with the first signature
 * in the structure
 *
 * @param   sign        The sign object to verify
 * @param   key         The key to verify with
 * @param   buf         Buffer to write in
 * @param   len         Size of the buffer to write in
 */
int cose_sign_verify_first(cose_sign_t* sign, cose_key_t *key, uint8_t *buf, size_t len);

/**
 * Retrieve a header from a sign object by key lookup
 *
 * @param   sign        The sign object to operate on
 * @param   hdr     hdr struct to fill
 * @param   key         The key to look up
 *
 * @return              A header object with matching key
 * @return              NULL if there is no header with the key
 */
bool cose_sign_get_header(cose_sign_t *sign, cose_hdr_t *hdr, int32_t key);

/**
 * Retrieve a protected header from a sign object by key lookup
 *
 * @param       sign        The sign object to operate on
 * @param[out]  hdr         Header to fill with the values
 * @param       key         The key to look up
 *
 * @return              A protected header object with matching key
 * @return              NULL if there is no protected header with the key
 */
bool cose_sign_get_protected(cose_sign_t *sign, cose_hdr_t *hdr, int32_t key);

/**
 * Retrieve an unprotected header from a sign object by key lookup
 *
 * @param       sign        The sign object to operate on
 * @param[out]  hdr         Header to fill with the values
 * @param       key         The key to look up
 *
 * @return              A protected header object with matching key
 * @return              NULL if there is no protected header with the key
 */
bool cose_sign_get_unprotected(cose_sign_t *sign, cose_hdr_t *hdr, int32_t key);

/**
 * Internal function to check if the object is a sign1 structure
 *
 * @param   sign        Sign object to check
 *
 * @return              True if the object is a sign1 object
 */
static inline bool _is_sign1(cose_sign_t *sign)
{
    return (sign->flags & COSE_FLAGS_SIGN1);
}

/* Header setters */

/**
 * Add a header to the protected bucket
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   sign        The sign object to operate on
 * @param   hdr         The hdr to add
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline void cose_sign_insert_prot(cose_sign_t *sign, cose_hdr_t *hdr)
{
    cose_hdr_insert(&sign->hdrs.prot.c, hdr);
}

/**
 * Add a header to the unprotected bucket
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   sign        The sign object to operate on
 * @param   hdr         The hdr to add
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline void cose_sign_insert_unprot(cose_sign_t *sign, cose_hdr_t *hdr)
{
    cose_hdr_insert(&sign->hdrs.unprot.c, hdr);
}

#ifdef __cplusplus
}
#endif

#endif

/** @} */
