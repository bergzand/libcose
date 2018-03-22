/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <string.h>
#include "cn-cbor/cn-cbor.h"

cn_cbor *cn_cbor_tag_create(int tag, cn_cbor *child, cn_cbor_context *ct, cn_cbor_errback *perr)
{
    cn_cbor *cn_tag = ct->calloc_func(1, sizeof(cn_cbor), ct->context);

    if (cn_tag == NULL) {
        if (perr != NULL) {
            perr->err = CN_CBOR_ERR_OUT_OF_MEMORY;
        }
        return NULL;
    }

    cn_tag->type = CN_CBOR_TAG;
    cn_tag->v.sint = tag;
    cn_tag->first_child = child;
    child->parent = cn_tag;

    return cn_tag;
}

void cn_cbor_data_replace(cn_cbor *cn_data, void *data)
{
    memcpy((uint8_t *)cn_data->v.bytes, data, cn_data->length);
}

