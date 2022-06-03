/*
 * Copyright (C) 2022 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cryto_tinycrypt Crypto glue layer, tinycrypt definitions
 * @ingroup     cose_crypto
 *
 * Crypto function api for glueing tinycrypt
 * @{
 *
 * @file
 * @brief       Crypto function api for glueing tinycrypt.
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 */

#ifndef COSE_CRYPTO_HASH_SIGS_H
#define COSE_CRYPTO_HASH_SIGS_H

#include "hash_sig_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name list of provided algorithms
 *
 * @{
 */
#define HAVE_ALGO_HSSLMS     /**< HSS/LMS support*/
/** @} */

/**
 * @brief HSS/LMS key sizes
 */
#define COSE_CRYPTO_HSSLMS_PUBLICKEYBYTES               (HSS_MAX_PUBLIC_KEY_LEN)
#define COSE_CRYPTO_HSSLMS_SECRETKEYBYTES               (PRIVATE_KEY_LEN)
/** @} */

#ifdef __cplusplus
}
#endif

#endif

/** @} */
