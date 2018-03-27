/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_H
#define COSE_H

#include <stdlib.h>
#include <stdint.h>
#include "cose_defines.h"
#include "cn-cbor/cn-cbor.h"


#ifndef COSE_SIGNATURES_MAX
#define COSE_SIGNATURES_MAX    4
#endif /* COSE_SIGNATURES_MAX */

#ifndef COSE_SIGN_HDR_MAX
#define COSE_SIGN_HDR_MAX 8
#endif /* COSE_SIGN_HDR_PROTECTED_MAX */

#ifndef COSE_MSGSIZE_MAX
#define COSE_MSGSIZE_MAX    2048
#endif /* COSE_MSGSIZE_MAX */

/**
 * COSE signer object
 */
typedef struct cose_signer {
    cose_kty_t kty; /** Key type */
    cose_curve_t crv;    /** Curve, algo is derived from this */
    uint8_t *kid;   /** Key identifier */
    size_t kid_len; /** length of the key identifier */
    uint8_t *x;     /** Public key part 1, must match the expected size of the algorithm */
    uint8_t *y;     /** Public key part 2, when not NULL, must match the expected size of the algorithm */
    uint8_t *d;     /** Private key, must match the expected size of the algorithm */
} cose_signer_t;

typedef struct cose_hdr {
    int32_t key;                /* Header label */
    cose_hdr_type_t type;       /* Type of the header */
    uint8_t flags;              /* Flags for the header */
    union {                     /* Depending on the type, the content is a pointer or an integer */
        int32_t value;            /* Direct integer value */
        const uint8_t *data;          /* Pointer to the content */
        const char *str;              /* String type content */
        cn_cbor *cbor;          /* cbor type data */
    } v;
    size_t len;                 /* Length of the data, only used for the bytes type */
} cose_hdr_t;

/**
 * Readily received or supplied signature structure
 */
typedef struct cose_signature {
    const cose_signer_t *signer;
    const uint8_t *hdr_protected;
    size_t hdr_protected_len;
    cn_cbor *hdr_unprotected;
    const uint8_t *signature;
    size_t signature_len;
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
    const uint8_t *hdr_prot_ser; /* Serialized form of the protected header */
    size_t hdr_prot_ser_len;     /* Length of the serialized protected header */
    uint8_t *ext_aad;
    uint16_t flags;              /* Flags as defined */
    size_t ext_aad_len;
    cose_hdr_t hdrs[COSE_SIGN_HDR_MAX];
    cose_signature_t sigs[COSE_SIGNATURES_MAX];  /** Signer data pointer */
    uint8_t num_sigs;
} cose_sign_t;

void cose_signer_init(cose_signer_t *signer);

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
 size_t cose_sign_get_kid(cose_sign_t *sign, uint8_t idx, const uint8_t **kid);

/**
 * Verify the idx't signature of the signed data with the supplied signer object
 */
int cose_sign_verify(cose_sign_t *sign, cose_signer_t *signer, uint8_t idx, cn_cbor_context *ct);

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

static inline bool cose_flag_isset(uint16_t flags, uint16_t flag)
{
    return flags & flag;
}

#endif
