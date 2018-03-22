/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <stdlib.h>


#include "CUnit/CUnit.h"
#include "CUnit/Basic.h"
#include "cose/test.h"

/* External list of tests */
extern test_t tests_sign[];
extern test_t tests_crypto[];


int add_tests(CU_pSuite pSuite, const test_t* tests)
{
   /* add the tests to the suite */
    for(int i = 0; tests[i].n !=NULL; i++) {
        if(!(CU_add_test(pSuite, tests[i].n, tests[i].f))) {
            printf("Error adding function %s\n",tests[i].n);
            CU_cleanup_registry();
            return CU_get_error();
        }
    }
    return 0;
}
int main()
{
    CU_pSuite pSuite = NULL;
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("Suite_crypto", NULL, NULL);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    add_tests(pSuite, tests_crypto);

    pSuite = CU_add_suite("Suite_signatures", NULL, NULL);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    add_tests(pSuite, tests_sign);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    printf("\n");
    //CU_basic_show_failures(CU_get_failure_list());
    printf("\n\n");

    CU_cleanup_registry();
    return CU_get_error();
}
