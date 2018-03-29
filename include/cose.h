/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_H
#define COSE_H

#ifndef COSE_SIGNATURES_MAX
#define COSE_SIGNATURES_MAX    4
#endif /* COSE_SIGNATURES_MAX */

#ifndef COSE_HDR_MAX
#define COSE_HDR_MAX 4
#endif /* COSE_HDR_MAX */

/*
 * @brief Combined maximum number of protected and unprotected headers in a
 * COSE sign object
 */
#ifndef COSE_SIGN_HDR_MAX
#define COSE_SIGN_HDR_MAX COSE_HDR_MAX
#endif /* COSE_SIGN_HDR_MAX */

/*
 * @brief Combined maximum number of protected and unprotected headers in a
 * COSE sign signature object
 */
#ifndef COSE_SIG_HDR_MAX
#define COSE_SIG_HDR_MAX  COSE_HDR_MAX
#endif /* COSE_SIG_HDR_MAX */

#ifndef COSE_MSGSIZE_MAX
#define COSE_MSGSIZE_MAX    512
#endif /* COSE_MSGSIZE_MAX */

#include <stdlib.h>
#include <stdint.h>
#include "cose_defines.h"
#include "cose/hdr.h"
#include "cose/sign.h"
#include "cose/signer.h"
#include "cn-cbor/cn-cbor.h"


static inline bool cose_flag_isset(uint16_t flags, uint16_t flag)
{
    return flags & flag;
}

#endif
