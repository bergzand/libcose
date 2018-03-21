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

/**
 */
void cose_crypto_sign(uint8_t *sign, unsigned long long int *signlen, uint8_t *msg, unsigned long long int msglen, uint8_t *skey);
int cose_crypto_verify(uint8_t *sign, uint8_t *msg, uint64_t msglen,  uint8_t *pkey);
void cose_crypto_keypair(uint8_t *pk, uint8_t *sk);
