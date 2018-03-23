/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Generic crypto function api for glueing purposes.
 */

#include <stdlib.h>
#include <stdint.h>
#ifdef CRYPTO_SODIUM
#include <sodium.h>
#elif defined(CRYPO_TWEETNACL)
#include <tweetnacl.h>
#endif

/**
 */
void cose_crypto_sign_ed25519(uint8_t *sign, size_t *signlen, uint8_t *msg, unsigned long long int msglen, uint8_t *skey);
int cose_crypto_verify_ed25519(const uint8_t *sign, uint8_t *msg, uint64_t msglen,  uint8_t *pkey);
void cose_crypto_keypair_ed25519(uint8_t *pk, uint8_t *sk);
size_t cose_crypto_sig_size_ed25519(void);
