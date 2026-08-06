/*
 * Copyright (C) 2026 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        nanocbor_byteorder.h
 * @brief       Byte-order helpers for nanocbor in the secure image.
 *
 * The Cortex-M33 is little-endian, so host <-> big-endian is a byte swap.
 * nanocbor pulls these in through NANOCBOR_BYTEORDER_HEADER; we provide them
 * with compiler builtins because <endian.h> is not available here.
 *
 * @author      Jan Thies <jan.thies@haw-hamburg.de>
 */

#ifndef NANOCBOR_BYTEORDER_H
#define NANOCBOR_BYTEORDER_H

#include <stdint.h>

#define htobe16(x) __builtin_bswap16((uint16_t)(x))
#define htobe32(x) __builtin_bswap32((uint32_t)(x))
#define htobe64(x) __builtin_bswap64((uint64_t)(x))
#define be64toh(x) __builtin_bswap64((uint64_t)(x))

#endif /* NANOCBOR_BYTEORDER_H */
