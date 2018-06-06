/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cryto_tweetnacl Crypto glue layer, tweetnacl definitions
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

#ifndef COSE_CRYPTO_HACL_H
#define COSE_CRYPTO_HACL_H

#include <haclnacl.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name list of provided algorithms
 *
 * @{
 */
#define HAVE_ALGO_SALSA20POLY1305
#define HAVE_ALGO_CHACHA20POLY1305
#define HAVE_ALGO_EDDSA
/** @} */

/**
 * @name Size definitions
 * @{
 */
#define COSE_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES 32
#define COSE_CRYPTO_SIGN_ED25519_SECRETKEYBYTES 64
#define COSE_CRYPTO_SIGN_ED25519_SIGNBYTES      64

#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES 32
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES 12
#define COSE_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES 16
/** @} */

#ifdef __cplusplus
}
#endif

#endif

/** @} */

