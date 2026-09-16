/*
 * Copyright (C) 2024 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup
 * @defgroup       <name> <description>
 * @{
 *
 * @file        tee_io_sanitizer.h
 * @brief
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 */

#ifndef TEE_IO_SANITIZER_H
#define TEE_IO_SANITIZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <arm_cmse.h>

/**
 * @brief Needs to be defined as 18 for address range check
 *
 * Source: https://arm-software.github.io/acle/cmse/cmse.html#address-range-check-intrinsic-for-cmse
 */
#define CMSE_NONSECURE              18

/**
 * @brief   Granularity at which the SPU attributes memory
 *
 * RAM is split into 8 KiB regions, flash into 32 KiB regions. Splitting at the
 * smaller of the two is safe for both.
 */
#define TEE_IO_REGION_SIZE          (0x2000)

/**
 * @brief   Check that a caller supplied range is non-secure memory
 *
 * cmse_check_address_range() compares the TT result of the first and the last
 * byte and fails when they differ, which is the case as soon as a range spans
 * two regions - even when both of them are non-secure. Callers hand in buffers
 * at arbitrary addresses, so check the range one region at a time.
 *
 * @param   addr    Start of the range
 * @param   len     Length of the range in bytes
 *
 * @return  @p addr if the whole range is non-secure, NULL otherwise
 */
static inline void *tee_check_ns_range(const void *addr, size_t len)
{
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + len;

    if (len == 0) {
        return (void *)addr;
    }

    if (end < start) {
        return NULL;
    }

    while (start < end) {
        uintptr_t next = (start + TEE_IO_REGION_SIZE) & ~((uintptr_t)TEE_IO_REGION_SIZE - 1);
        size_t chunk = ((next < end) ? next : end) - start;

        if (cmse_check_address_range((void *)start, chunk, CMSE_NONSECURE) == NULL) {
            return NULL;
        }
        start += chunk;
    }

    return (void *)addr;
}

#ifdef __cplusplus
}
#endif

#endif /* TEE_IO_SANITIZER_H */
/** @} */
