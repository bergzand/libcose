/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cryto_sodium Crypto glue layer, sodium definitions
 * @ingroup     cose_crypto
 *
 * Crypto function api for glueing libsodium.
 * @{
 *
 * @file
 * @brief       Crypto function api for glueing libsodium.
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef COSE_CRYPTO_SODIUM_H
#define COSE_CRYPTO_SODIUM_H

#include "cose/crypto/sodium.h"

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

#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES crypto_aead_chacha20poly1305_IETF_ABYTES

#ifdef __cplusplus
}
#endif

#endif

/** @} */
