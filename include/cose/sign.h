/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * Internal constants for signing
 */

const char SIG_TYPE_SIGNATURE[] = "Signature";
const char SIG_TYPE_SIGNATURE1[] = "Signature1";
const char SIG_TYPE_COUNTERSIGNATURE[] = "CounterSignature";

/* Strip zero terminators */
#define COSE_SIGN_STR_SIGNATURE_LEN         (sizeof(signature)-1)
#define COSE_SIGN_STR_SIGNATURE1_LEN        (sizeof(signature1)-1)
#define COSE_SIGN_STR_COUNTERSIGNATURE_LEN  (sizeof(countersignature)-1)


