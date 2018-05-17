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

#include <cbor.h>
#include "cose_defines.h"
#include "cose/hdr.h"
#include "cose/recipient.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

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
    const uint8_t *payload;                     /**< Pointer to the payload to encrypt */
    size_t payload_len;                         /**< Size of the payload */
    uint8_t *ext_aad;                           /**< Pointer to the additional authenticated data */
    size_t ext_aad_len;                         /**< Size of the AAD */
    uint16_t flags;                             /**< Flags as defined */
    uint8_t *cek;                               /**< Pointer to the content encryption key */
    cose_algo_t algo;                           /**< Algo used for the base encrypt structure */
    uint8_t *nonce;                             /**< Possible Nonce to use */
    uint8_t num_recps;                          /**< Number of recipients to encrypt for */
    cose_headers_t hdrs;                        /**< Headers included in the body */
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
 * @param   len         The length of the payload in bytes
 */
void cose_encrypt_set_payload(cose_encrypt_t *encrypt, const void *payload, size_t len);

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
ssize_t cose_encrypt_encode(cose_encrypt_t *encrypt, uint8_t *buf, size_t len, uint8_t *nonce, uint8_t **out);

/**
 * cose_encrypt_decode decodes a buffer containing a COSE encrypt object into
 * into a cose_encrypt_t struct
 *
 * @param[out]  encrypt     Encrypt struct to fill
 * @param       buf         Buffer to read from
 * @param       len         Size of the buffer
 * @param       ct          CN_CBOR context for cbor block allocation
 *
 * @return                  COSE_OK when successful
 */
int cose_encrypt_decode(cose_encrypt_t *encrypt, uint8_t *buf, size_t len);

/**
 * cose_encrypt_decrypt tries to verify and decrypt the payload of a
 * cose_encrypt_t object
 *
 * @param       encrypt     Encrypt struct to work on
 * @param       key         Key to use for decryption
 * @param       buf         Temporary buffer to use for serialized intermediates
 * @param       len         Size of the temporary buffer
 * @param[out]  payload     Buffer to write the plaintext payload to
 * @param[out]  payload_len Size of the plaintext
 *
 * @return                  COSE_OK on successful verification and decryption
 */
int cose_encrypt_decrypt(cose_encrypt_t *encrypt, cose_key_t *key, unsigned idx, uint8_t *buf, size_t len, uint8_t *payload, size_t *payload_len);
#endif

/** @} */
