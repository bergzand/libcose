/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_CBOR_H
#define COSE_CBOR_H

#include "cn-cbor/cn-cbor.h"


cn_cbor * cn_cbor_tag_create(int tag, cn_cbor * child, cn_cbor_context *ct, cn_cbor_errback * perr);

#endif
