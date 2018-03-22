/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef COSE_DEFINES_H
#define COSE_DEFINES_H

typedef enum {
    COSE_OK = 0, /* Everything okay */
    COSE_ERR_NOMEM,  /* No memory for operation */
    COSE_ERR_CRYPTO, /* Crypto error, e.g. invalid signature */
} cose_err_t;

/**
 * @brief COSE common flags
 * @{
 */
#define COSE_FLAGS_EXTDATA   0x8000
#define COSE_FLAGS_UNTAGGED  0x4000
/**
 * @}
 */

typedef enum {
	COSE_UNKNOWN = 0,
	COSE_SIGN = 98,
	COSE_SIGN1 = 18,
	COSE_ENVELOPED = 96,
	COSE_ENCRYPT = 16,
	COSE_MAC = 97,
	COSE_MAC0 = 17,
} cose_cbor_tag_t;

/**
 * COSE header parameters according to rfc 8152
 *
 * @url https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
typedef enum {
    COSE_HDR_ALG         = 1,
    COSE_HDR_CRIT        = 2,
    COSE_HDR_CONTENT     = 3,
    COSE_HDR_KID         = 4,
    COSE_HDR_IV          = 5,
    COSE_HDR_PARTIALIV   = 6,
    COSE_HDR_COUNTERSIG  = 7,
    COSE_HDR_UNASSIGN    = 8,
    COSE_HDR_COUNTERSIG0 = 9,
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
    COSE_EC_CURVE_P256    = 1, /** secp256r1 */
    COSE_EC_CURVE_P384    = 2, /** secp384r1 */
    COSE_EC_CURVE_P521    = 3, /** secp521r1 */
    COSE_EC_CURVE_X22519  = 4, /** X25519, ECDH only */
    COSE_EC_CURVE_X448    = 5, /** X448, ECDH only */
    COSE_EC_CURVE_ED25519 = 6, /** Ed25519 for EdDSA only */
    COSE_EC_CURVE_ED448   = 7, /** Ed25519 for EdDSA only */
} cose_curve_t;

typedef enum {
    COSE_ALGO_ES512       = -36, /** ECDSA w/ SHA512 */
    COSE_ALGO_ES384       = -35, /** ECDSA w/ SHA384 */
    COSE_ALGO_ES256       = -7,  /** ECDSA w/ SHA256 */
    COSE_ALGO_EDDSA       = -8,  /** EdDSA */
} cose_algo_t;

#endif
