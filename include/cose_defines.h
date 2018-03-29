/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_DEFINES_H
#define COSE_DEFINES_H

typedef enum {
    COSE_OK                 = 0,    /* Everything okay */
    COSE_ERR_NOMEM          = -1,   /* No memory for operation, e.g. allocator out of mem */
    COSE_ERR_CRYPTO         = -2,   /* Crypto error, e.g. invalid signature */
    COSE_ERR_NOINIT         = -3,   /* Initialization error */
    COSE_ERR_INVALID_CBOR   = -4,   /* CBOR related error */
    COSE_ERR_CBOR_NOTSUP    = -5,   /* CBOR unsupported error */
    COSE_ERR_INVALID_PARAM  = -6,   /* Invalid parameter passed to function */
    COSE_ERR_NOT_FOUND      = -7,   /* Header not found */
} cose_err_t;

/**
 * @brief COSE common flags
 * @{
 */
#define COSE_FLAGS_EXTDATA   0x8000
#define COSE_FLAGS_UNTAGGED  0x4000

#define COSE_FLAGS_SIGN1     0x0001
/**
 * @}
 */

typedef enum {
    COSE_UNKNOWN    = 0,
    COSE_SIGN       = 98,
    COSE_SIGN1      = 18,
    COSE_ENVELOPED  = 96,
    COSE_ENCRYPT    = 16,
    COSE_MAC        = 97,
    COSE_MAC0       = 17,
} cose_cbor_tag_t;


typedef enum {
    COSE_HDR_TYPE_INT,  /**< Integer type header */
    COSE_HDR_TYPE_TSTR, /**< Text string type header */
    COSE_HDR_TYPE_BSTR, /**< Byte string type header */
    COSE_HDR_TYPE_CBOR, /**< CBOR type header */
} cose_hdr_type_t;

#define COSE_HDR_FLAGS_PROTECTED     0x01 /* Header is in the protected bucket
                                           * or in the unprotected if not set */

/**
 * COSE header parameters according to rfc 8152
 *
 * @url https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
typedef enum {
    COSE_HDR_ALG            = 1,
    COSE_HDR_CRIT           = 2,
    COSE_HDR_CONTENT_TYPE   = 3,
    COSE_HDR_KID            = 4,
    COSE_HDR_IV             = 5,
    COSE_HDR_PARTIALIV      = 6,
    COSE_HDR_COUNTERSIG     = 7,
    COSE_HDR_UNASSIGN       = 8,
    COSE_HDR_COUNTERSIG0    = 9,
} cose_header_param_t;

/**
 * COSE Key common parameters
 *
 * @url https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 */
typedef enum {
    COSE_KEY_PARAM_KTY  = 1,    /** Key type identifier */
    COSE_KEY_PARAM_KID  = 2,    /** Key identifier */
    COSE_KEY_PARAM_ALGO = 3,    /** Key algorithm */
    COSE_KEY_PARAM_OPS  = 4,    /** Key options */
    COSE_KEY_PARAM_BIV  = 5,    /** Base IV */
} cose_key_param_t;

/**
 * COSE key types according to rfc 8152
 *
 * @url https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
typedef enum {
    COSE_KTY_OCTET  = 1,    /** Octet key pair (eddsa) */
    COSE_KTY_EC2    = 2,    /** Elliptic curve */
    COSE_KTY_RSA    = 3,    /** RSA */
    COSE_KTY_SYMM   = 4,    /** Symmetric key types */
} cose_kty_t;

typedef enum {
    COSE_EC_CURVE_P256      = 1,    /** secp256r1 */
    COSE_EC_CURVE_P384      = 2,    /** secp384r1 */
    COSE_EC_CURVE_P521      = 3,    /** secp521r1 */
    COSE_EC_CURVE_X22519    = 4,    /** X25519, ECDH only */
    COSE_EC_CURVE_X448      = 5,    /** X448, ECDH only */
    COSE_EC_CURVE_ED25519   = 6,    /** Ed25519 for EdDSA only */
    COSE_EC_CURVE_ED448     = 7,    /** Ed25519 for EdDSA only */
} cose_curve_t;

typedef enum {
    COSE_ALGO_ES512 = -36,          /** ECDSA w/ SHA512 */
    COSE_ALGO_ES384 = -35,          /** ECDSA w/ SHA384 */
    COSE_ALGO_ES256 = -7,           /** ECDSA w/ SHA256 */
    COSE_ALGO_EDDSA = -8,           /** EdDSA */
} cose_algo_t;

#endif
