/*
 * Copyright (C) 2019 Koen Zandberg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cryto_monocypher Crypto glue layer, Monocypher definitions
 * @ingroup     cose_crypto
 *
 * Crypto function api for glueing Monocypher.
 * @{
 *
 * @file
 * @brief       Crypto function api for glueing Monocypher.
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_CRYPTO_MONOCYPHER_H
#define COSE_CRYPTO_MONOCYPHER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name list of provided algorithms
 *
 * @{
 */
#define HAVE_ALGO_CHACHA20POLY1305
#define HAVE_ALGO_EDDSA
/** @} */

#ifdef __cplusplus
}
#endif

#endif

/** @} */
