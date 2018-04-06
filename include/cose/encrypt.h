/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_encrypt COSE encrypt defintions
 * @ingroup     cose
 * constants for encryption
 * @{
 *
 * @file
 * @brief       API definitions for COSE encryption objects
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_ENCRYPT_H
#define COSE_ENCRYPT_H

#include "cose.h"

/**
 * @name COSE recipient struct
 *
 * This struct produces the following CDDL:
 * ```
 *  COSE_recipient = [
 *      Headers,
 *      ciphertext : bstr / nil,
 *      ? recipients : [+COSE_recipient]
 *  ]
 * ```
 */


/**
 * @name COSE encrypt,
 * https://tools.ietf.org/html/rfc8152#section-5
 *
 * This struct produces the following CDDL:
 * ```
 *    COSE_Encrypt = [
 *      Headers,
 *      ciphertext : bstr / nil,
 *      recipients : [+COSE_recipient]
 *  ]
 * ```
 *
 * @brief Struct for conversion to both the COSE encrypt and COSE encrypt0 objects.
 * @{
 */
typedef struct cose_encrypt {
    const uint8_t *payload;                        /**< Pointer to the payload to encrypt */
    size_t payload_len;                         /**< Size of the payload */
    uint8_t *ext_aad;                           /**< Pointer to the additional authenticated data */
    size_t ext_aad_len;                         /**< Size of the AAD */
    const uint8_t *hdr_prot_ser;                /**< Serialized form of the protected header */
    size_t hdr_prot_ser_len;                    /**< Length of the serialized protected header */
    uint16_t flags;                             /**< Flags as defined */
    uint8_t *cek;                               /**< Pointer to the content encryption key */
    cose_algo_t algo;                           /**< Algo used for the base encrypt structure */
    uint8_t *nonce;                             /**< Possible Nonce to use */
    uint8_t num_recps;                          /**< Number of recipients to encrypt for */
    cose_hdr_t hdrs[COSE_ENCRYPT_HDR_MAX];      /**< Headers included in the body */
    cose_recp_t recps[COSE_RECIPIENTS_MAX];     /**< recipient data array */
} cose_encrypt_t;
/** @} */


/**
 * cose_encrypt_init initializes an cose encrypt struct
 *
 * @param   encrypt     encrypt struct to initialize
 */
void cose_encrypt_init(cose_encrypt_t *encrypt);

/**
 * cose_encrypt_set_payload sets the payload pointer of the COSE encrypt struct
 *
 * @param   encrypt     Encrypt struct to set the payload for
 * @param   payload     The payload to set
 * @param   len         The length of the payload
 */
void cose_encrypt_set_payload(cose_encrypt_t *encrypt, void *payload, size_t len);

/**
 * cose encrypt_get_algo returns the algorithm used in the encrypt package
 *
 * @param   encrypt     Encrypt struct to retrieve from
 *
 * @return              Algorithm used
 */
cose_algo_t cose_encrypt_get_algo(const cose_encrypt_t *encrypt);


/**
 * cose_encrypt_add_recipient adds an recipient as an key to an encrypt object
 *
 * @param   encrypt     Encrypt struct to operate on
 * @param   key         The key to add as recipient
 *
 * @return              Negative when failed
 */
int cose_encrypt_add_recipient(cose_encrypt_t *encrypt, const cose_key_t *key);

/**
 * cose_encrypt_set_algo sets the algo to encrypt with
 *
 * @param   encrypt     Encrypt struct to operate on
 * @param   algo        The algo to use on the encrypt body
 */
void cose_encrypt_set_algo(cose_encrypt_t *encrypt, cose_algo_t algo);

/**
 * cose_encrypt_encode builds the COSE encrypt packet from the encrypt struct
 *
 * @param       encrypt     Encrypt struct to encode
 * @param       buf         Buffer to write into
 * @param       len         Size of the buffer
 * @param       nonce       Nonce to use in the encryption
 * @param[out]  out         Pointer to the final COSE encrypt object
 * @param       ct          CN_CBOR context for cbor block allocation
 *
 * @return                  Size of the COSE encrypt object
 * @return                  Negative on failure
 */
ssize_t cose_encrypt_encode(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, uint8_t *nonce, uint8_t **out, cn_cbor_context *ct);

#endif

/** @} */
