/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */


/**
 * @defgroup cose COSE common definitions
 *
 *
 * @{
 * @file
 * @brief COSE common definitions
 */
#ifndef COSE_H
#define COSE_H

#ifndef COSE_SIGNATURES_MAX
#define COSE_SIGNATURES_MAX    4 /**< Maximum number of signatures in a single sign object */
#endif /* COSE_SIGNATURES_MAX */

#ifndef COSE_HDR_MAX
#define COSE_HDR_MAX 4 /**< Default maximum number of headers in a COSE object */
#endif /* COSE_HDR_MAX */

#ifndef COSE_SIGN_HDR_MAX
#define COSE_SIGN_HDR_MAX COSE_HDR_MAX /**< Combined maximum number of protected and unprotected headers in a COSE signature body */
#endif /* COSE_SIGN_HDR_MAX */

#ifndef COSE_SIG_HDR_MAX
#define COSE_SIG_HDR_MAX  COSE_HDR_MAX /**< Combined maximum number of protected and unprotected headers in a COSE sig struct */
#endif /* COSE_SIG_HDR_MAX */

#ifndef COSE_MSGSIZE_MAX
#define COSE_MSGSIZE_MAX    512 /**< Maximum payload in a COSE object */
#endif /* COSE_MSGSIZE_MAX */

#include <stdlib.h>
#include <stdint.h>
#include "cose_defines.h"
#include "cose/hdr.h"
#include "cose/sign.h"
#include "cose/signer.h"
#include "cn-cbor/cn-cbor.h"

#endif

/** @} */
