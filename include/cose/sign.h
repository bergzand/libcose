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
 * Internal constants for signing
 * @{
 *
 * @file
 * @brief       API definitions for COSE signing objects
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_SIGN_H
#define COSE_SIGN_H

#include "cose/hdr.h"
#include "cose/signer.h"

/**
 * @name Signature struct
 * @brief Contains signature and headers related to the signatures
 * @{
 */
typedef struct cose_signature {
    const uint8_t *hdr_protected;       /**< Pointer to the protected header */
    size_t hdr_protected_len;           /**< Protected header length */
    const uint8_t *signature;           /**< Pointer to the signature */
    size_t signature_len;               /**< Length of the signature */
    const cose_signer_t *signer;        /**< Pointer to the signer used for this signature */
    cose_hdr_t hdrs[COSE_SIG_HDR_MAX];  /**< Headers included in this signature */
} cose_signature_t;
/** @} */


/**
 * @name COSE sign,
 * https://tools.ietf.org/html/rfc8152#section-4
 *
 * @brief Struct for conversion to both the COSE sign1 and COSE sign objects.
 * @{
 */
typedef struct cose_sign {
    const void *payload;                        /**< Pointer to the payload */
    size_t payload_len;                         /**< Size of the payload */
    uint8_t *ext_aad;                           /**< Pointer to the additional authenticated data */
    size_t ext_aad_len;                         /**< Size of the AAD */
    const uint8_t *hdr_prot_ser;                /**< Serialized form of the protected header */
    size_t hdr_prot_ser_len;                    /**< Length of the serialized protected header */
    uint16_t flags;                             /**< Flags as defined */
    uint8_t num_sigs;                           /**< Number of signatures to sign with */
    cose_hdr_t hdrs[COSE_SIGN_HDR_MAX];         /**< Headers included in the body */
    cose_signature_t sigs[COSE_SIGNATURES_MAX]; /**< Signer data array */
} cose_sign_t;
/** @} */

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
 * @param len       The length of the payload
 */
void cose_sign_set_payload(cose_sign_t *sign, void *payload, size_t len);

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
 * cose_sign_add_signer adds a signer to the sign struct to sign with
 *
 * @param sign      Sign struct to operate on
 * @param signer    The signer to sign with
 *
 * @return          0 on success
 * @return          negative on failure
 */
int cose_sign_add_signer(cose_sign_t *sign, const cose_signer_t *signer);

/**
 * cose_sign_sign signs the data from the sign object with the attached
 * signers. The output is placed in the out param, up to s_out bytes are
 * written
 *
 * @param   sign    Sign struct to encode
 * @param   buf     Buffer to write in
 * @param   len     Size of the buffer to write in
 * @param   ct      CN_CBOR context for cbor block allocation
 *
 * @return          The number of bytes written
 * @return          Negative on error
 */
ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t len, cn_cbor_context *ct);

/**
 * cose_sign_decode parses a buffer to a cose sign struct. This buffer can
 * contain both a tagged sign cbor byte string or an untagged byte string
 *
 * @param   sign    Sign struct to fill
 * @param   buf     The buffer to read
 * @param   len     Length of the buffer
 * @param   ct      CN_CBOR context for cbor block allocation
 *
 * @return          0 on success
 * @return          negative on failure
 */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len, cn_cbor_context *ct);

/**
 * Get the key ID from a signature
 *
 * @param      sign     Sign struct to check
 * @param      idx      Signature slot to fetch
 * @param[out] kid      Filled with a pointer to the key ID
 *
 * @return              Size of the key ID
 * @return              0 in case of no key ID
 */
ssize_t cose_sign_get_kid(cose_sign_t *sign, uint8_t idx, const uint8_t **kid);

/**
 * Verify the idx't signature of the signed data with the supplied signer object
 *
 * @param   sign        The sign object to verify
 * @param   signer      The signer to verify with
 * @param   idx         The signature index to verify from the sign object
 * @param   ct          CN_CBOR context for cbor block allocation
 *
 * @return              0 on verification success
 * @return              Negative on error
 */
int cose_sign_verify(cose_sign_t *sign, cose_signer_t *signer, uint8_t idx, cn_cbor_context *ct);

/**
 * Retrieve a header from a sign object by key lookup
 *
 * @param   sign        The sign object to operate on
 * @param   key         The key to look up
 *
 * @return              A header object with matching key
 * @return              NULL if there is no header with the key
 */
cose_hdr_t *cose_sign_get_header(cose_sign_t *sign, int32_t key);

/**
 * Retrieve a protected header from a sign object by key lookup
 *
 * @param   sign        The sign object to operate on
 * @param   key         The key to look up
 *
 * @return              A protected header object with matching key
 * @return              NULL if there is no protected header with the key
 */
cose_hdr_t *cose_sign_get_protected(cose_sign_t *sign, int32_t key);


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
 * Add a header with an integer based value
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   sign        The sign object to operate on
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   value       Integer value to set for the new header
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline int cose_sign_add_hdr_value(cose_sign_t *sign, int32_t key, uint8_t flags, int32_t value)
{
    return cose_hdr_add_hdr_value(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, value);
}

/**
 * Add a header with a string based value
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   sign        The sign object to operate on
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   str         zero terminated string to set
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline int cose_sign_add_hdr_string(cose_sign_t *sign, int32_t key, uint8_t flags, char *str)
{
    return cose_hdr_add_hdr_string(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, str);
}

/**
 * Add a header with a byte array based value
 *
 * @note This function does not protect against setting duplicate keys
 *
 * @param   sign        The sign object to operate on
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   data        Byte array to set
 * @param   len         Length of the byte array
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline int cose_sign_add_hdr_data(cose_sign_t *sign, int32_t key, uint8_t flags, uint8_t *data, size_t len)
{
    return cose_hdr_add_hdr_data(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, data, len);
}

/**
 * Add a header with a CBOR based value
 *
 * @note This function does not protect against setting duplicate keys
 * @todo Properly copy the cbor struct to protect against freeing it
 *
 * @param   sign        The sign object to operate on
 * @param   key         The key to add
 * @param   flags       Flags to set for this header
 * @param   cbor        Pointer to the cbor object to set for the header
 *
 * @return              0 on success
 * @return              Negative when failed
 */
static inline int cose_sign_add_hdr_cbor(cose_sign_t *sign, int32_t key, uint8_t flags, cn_cbor *cbor)
{
    return cose_hdr_add_hdr_cbor(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, cbor);
}

/* Header setters for common headers */
/**
 * Set the content type number header of the sign body. The header is placed
 * in the protected bucket.
 *
 * This function adds a content type header or sets the current content type
 * header
 *
 * @param   sign        The sign object to operate on
 * @param   value       The integer value of the content type
 *
 * @return              0 on success
 * @return              Negative on error
 */
static inline int cose_sign_set_ct(cose_sign_t *sign, int32_t value)
{
    int res = COSE_OK;
    cose_hdr_t *hdr = cose_hdr_get(sign->hdrs, COSE_SIGN_HDR_MAX, COSE_HDR_CONTENT_TYPE);

    if (!hdr) {
        res = cose_sign_add_hdr_value(sign, COSE_HDR_CONTENT_TYPE, COSE_HDR_FLAGS_PROTECTED, value);
    }
    else {
        hdr->v.value = value;
        hdr->flags |= COSE_HDR_FLAGS_PROTECTED;
        hdr->type = COSE_HDR_TYPE_INT;
    }
    return res;
}

#endif

/** @} */
