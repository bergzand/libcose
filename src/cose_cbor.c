/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <string.h>
#include "cn-cbor/cn-cbor.h"

static bool _append_kv(cn_cbor *cb_map, cn_cbor *key, cn_cbor *val)
{
    //Connect key and value and insert them into the map.
    key->parent = cb_map;
    key->next = val;
    val->parent = cb_map;
    val->next = NULL;

    if (cb_map->last_child) {
        cb_map->last_child->next = key;
    }
    else {
        cb_map->first_child = key;
    }
    cb_map->last_child = val;
    cb_map->length += 2;
    return true;
}


/* Merge the second cn_cbor map into the first cn_cbor map */
bool cn_cbor_map_merge(cn_cbor *first, cn_cbor *second, cn_cbor_errback *perr)
{
    //Make sure input is a map. Otherwise
    if (!first || !second ||
        first->type != CN_CBOR_MAP ||
        second->type != CN_CBOR_MAP) {
        if (perr) {
            perr->err = CN_CBOR_ERR_INVALID_PARAMETER;
        }
        return false;
    }
    cn_cbor *cp;
    for (cp = second->first_child; cp && cp->next; cp = cp->next->next) {
        _append_kv(first, cp, cp->next);
    }
    second->first_child = NULL;
    second->last_child = NULL;
    return true;
}

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

