/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 * Copyright (C) 2020 Christian Amsüss <christian@amsuess.com> and Ericsson AB
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cryto_tinydtls Crypto glue layer, tinydtls definitions
 * @ingroup     cose_crypto
 *
 * Crypto function api for glueing tinydtls' AEAD functions.
 * @{
 *
 * @file
 * @brief       Crypto function api for glueing tinydtls.
 *
 * @author      Christian Amsüss <christian@amsuess.com>
 */

#ifndef COSE_CRYPTO_TINYDTLS_H
#define COSE_CRYPTO_TINYDTLS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name list of provided algorithms
 *
 * @{
 */
#define HAVE_ALGO_AESCCM_16_64_128 /**< AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce */
/** @} */

#ifdef __cplusplus
}
#endif

#endif

/** @} */
