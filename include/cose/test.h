/*
 * Copyright (C) 2018 Freie Universitat Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef COSE_TEST_H
#define COSE_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function prototype for a test function
 */
typedef void (*test_func)(void);

/**
 * Struct to define a test
 */
typedef struct test {
    const test_func f;  /**< Function to run as test */
    const char *n;      /**< Name or description of the test */
} test_t;

#ifdef __cplusplus
}
#endif

#endif
