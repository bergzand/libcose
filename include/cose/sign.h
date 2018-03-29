/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Internal constants for signing
 */

#ifndef COSE_SIGN_H
#define COSE_SIGN_H

#include "cose/hdr.h"
#include "cose/signer.h"

/**
 * Readily received or supplied signature structure
 */
typedef struct cose_signature {
    const uint8_t *hdr_protected;
    size_t hdr_protected_len;
    cn_cbor *hdr_unprotected;
    const uint8_t *signature;
    size_t signature_len;
    const cose_signer_t *signer;
    cose_hdr_t hdrs[COSE_SIG_HDR_MAX];
} cose_signature_t;

/**
 * COSE sign object,
 * https://tools.ietf.org/html/rfc8152#section-4
 *
 * Unified struct for both the sign1 and sign objects
 */
typedef struct cose_sign {
    const void *payload;
    size_t payload_len;
    uint8_t *ext_aad;
    size_t ext_aad_len;
    const uint8_t *hdr_prot_ser; /* Serialized form of the protected header */
    size_t hdr_prot_ser_len;     /* Length of the serialized protected header */
    uint16_t flags;              /* Flags as defined */
    uint8_t num_sigs;
    cose_hdr_t hdrs[COSE_SIGN_HDR_MAX];
    cose_signature_t sigs[COSE_SIGNATURES_MAX];  /** Signer data pointer */
} cose_sign_t;

static const char SIG_TYPE_SIGNATURE[] = "Signature";
static const char SIG_TYPE_SIGNATURE1[] = "Signature1";
static const char SIG_TYPE_COUNTERSIGNATURE[] = "CounterSignature";

/* Strip zero terminators */
#define COSE_SIGN_STR_SIGNATURE_LEN         (sizeof(signature)-1)
#define COSE_SIGN_STR_SIGNATURE1_LEN        (sizeof(signature1)-1)
#define COSE_SIGN_STR_COUNTERSIGNATURE_LEN  (sizeof(countersignature)-1)
/**
 * cose_sign_init initializes a sign struct
 *
 * @param sign     Empty sign struct to fill
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
 */
void cose_sign_set_external_aad(cose_sign_t *sign, void *ext, size_t len);

/**
 * cose_sign_add_signer adds a signature for the signer to the sign struct
 *
 * @note As this adds signatures, this should be done after the protected
 * headers, the payload and the external data is set.
 *
 * @param sign      Sign struct to operate on
 * @param signer    The signer to sign with
 * @param buf       A buffer to store the signature and related data in
 * @param bufsize   Length of the buffer
 * @param ct        Pointer to the cbor context
 * @param errp      Error back
 */
int cose_sign_add_signer(cose_sign_t *sign, const cose_signer_t *signer);

/**
 * cose_sign_sign signs the data from the sign object with the attached
 * signers. The output is placed in the out param, up to s_out bytes are
 * written
 */
ssize_t cose_sign_encode(cose_sign_t *sign, uint8_t *buf, size_t bufsize, cn_cbor_context *ct);

/**
 * cose_sign_decode parses a buffer to a cose sign struct. This buffer can
 * contain both a tagged sign cbor byte string or an untagged byte string
 *
 * @param sign      Sign struct to fill
 * @param buf       The buffer to read
 * @param len       Length of the buffer
 */
int cose_sign_decode(cose_sign_t *sign, const uint8_t *buf, size_t len, cn_cbor_context *ct);

/**
 * Get the key ID from a signature
 *
 * @param      sign     Sign struct to check
 * @param      idx      Signature slot to fetch
 * @param[out] kid      Filled with a pointer to the key ID
 * @return              Size of the key ID, 0 in case of empty slot
 */
ssize_t cose_sign_get_kid(cose_sign_t *sign, uint8_t idx, const uint8_t **kid);

/**
 * Verify the idx't signature of the signed data with the supplied signer object
 */
int cose_sign_verify(cose_sign_t *sign, cose_signer_t *signer, uint8_t idx, cn_cbor_context *ct);

cose_hdr_t *cose_sign_get_header(cose_sign_t *sign, int32_t key);
cose_hdr_t *cose_sign_get_protected(cose_sign_t *sign, int32_t key);

static inline bool _is_sign1(cose_sign_t *sign)
{
    return (sign->flags & COSE_FLAGS_SIGN1);
}


/* Header setters */
static inline int cose_sign_add_hdr_value(cose_sign_t *sign, int32_t key, uint8_t flags, int32_t value)
{
    return cose_hdr_add_hdr_value(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, value);
}

static inline int cose_sign_add_hdr_string(cose_sign_t *sign, int32_t key, uint8_t flags, char *str)
{
    return cose_hdr_add_hdr_string(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, str);
}

static inline int cose_sign_add_hdr_data(cose_sign_t *sign, int32_t key, uint8_t flags, uint8_t *data, size_t len)
{
    return cose_hdr_add_hdr_data(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, data, len);
}

static inline int cose_sign_add_hdr_cbor  (cose_sign_t *sign, int32_t key, uint8_t flags, cn_cbor *cbor)
{
    return cose_hdr_add_hdr_cbor(sign->hdrs, COSE_SIGN_HDR_MAX, key, flags, cbor);
}

/* Header setters for common headers */
/*
 * Set the content type number
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
