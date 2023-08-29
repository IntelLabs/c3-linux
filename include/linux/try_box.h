/*
 Copyright 2016 Intel Corporation
 SPDX-License-Identifier: MIT
*/
#ifndef MALLOC_TRY_BOX_H_
#define MALLOC_TRY_BOX_H_

#ifndef _CC_GLOBALS_NO_INCLUDES_
#include <stddef.h>
#include <stdio.h>
#endif
#include "cc_globals.h"  // NOLINT

static inline int try_box(uint64_t ptr, size_t size, ptr_metadata_t *md) {
    size_t max_off;
    uint64_t ptr_end;
    uint64_t diff;
    int leading_zeros_in_diff;
    uint8_t enc_size;
    size = (size < (1UL << MIN_ALLOC_OFFSET) ? (1UL << MIN_ALLOC_OFFSET)
                                             : size);

    max_off = size - 1;
    ptr_end = ptr + max_off;
    diff = ptr ^ ptr_end;
    leading_zeros_in_diff = (diff == 0 ? 64 : __builtin_clzl(diff));

    if (leading_zeros_in_diff < 64 - PLAINTEXT_SIZE) {
#ifndef _CC_GLOBALS_NO_INCLUDES_
#ifndef _EXCLUDE_IN_EDK2_BUILD_
        fprintf(stderr,
                "try_box: region is not boxable"
                " (leading_zeros_in_diff = %d, must be less than %d)\n",
                leading_zeros_in_diff, 64 - PLAINTEXT_SIZE);
#endif  // _EXCLUDE_IN_EDK2_BUILD_
#endif  // _CC_GLOBALS_NO_INCLUDES_
        return 0;
    }
    enc_size = (uint8_t)(64 - leading_zeros_in_diff - MIN_ALLOC_OFFSET);

    // adding 1 so we start with encoded size 0x1 correspoinding to 8B slot
    enc_size++;

    md->size_ = enc_size;
    // TODO(?): add special case of 4GB slot with adjust=1
    md->adjust_ = 0x0;
    return 1;
}

#endif  // MALLOC_TRY_BOX_H_
