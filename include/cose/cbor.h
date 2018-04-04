/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    cose_cbor COSE CBOR auxiliary functions
 * @ingroup     cose
 * @{
 *
 * @file
 * @brief       Extra cbor related functions
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */
#ifndef COSE_CBOR_H
#define COSE_CBOR_H

#include "cn-cbor/cn-cbor.h"

/**
 * Create a CBOR tag with chil as value
 *
 * @param   tag     tag number
 * @param   child   cbor struct to use as value
 * @param   ct      CN_CBOR context for cbor block allocation
 * @param   perr    error return struct from cn-cbor
 *
 * @return          A pointer to the allocated tag cbor struct
 */
cn_cbor *cn_cbor_tag_create(int tag, cn_cbor *child, cn_cbor_context *ct, cn_cbor_errback *perr);

#endif

/** @} */
