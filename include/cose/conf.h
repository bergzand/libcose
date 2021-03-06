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
#ifndef COSE_CONF_H
#define COSE_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef COSE_CBOR_VALIDATION
#define COSE_CBOR_VALIDATION   CborValidateStrictMode /**< tinycbor validate */
#endif

#ifndef COSE_SIGNATURES_MAX
#define COSE_SIGNATURES_MAX    4 /**< Maximum number of signatures in a single sign object */
#endif /* COSE_SIGNATURES_MAX */

#ifndef COSE_RECIPIENTS_MAX
#define COSE_RECIPIENTS_MAX    4 /**< Maximum number of signatures in a single sign object */
#endif /* COSE_RECIPIENTS_MAX */

#ifndef COSE_HDR_MAX
#define COSE_HDR_MAX 4 /**< Default maximum number of headers in a COSE object */
#endif /* COSE_HDR_MAX */

#ifndef COSE_MSGSIZE_MAX
#define COSE_MSGSIZE_MAX    512 /**< Maximum payload in a COSE object */
#endif /* COSE_MSGSIZE_MAX */

#ifdef __cplusplus
}
#endif

#endif
/** @} */
