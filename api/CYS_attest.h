/*
 * Copyright (C) 2026 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        CYS_attest.h
 * @brief       Non-secure entry for the secure-world attestation operation.
 *
 * @author      Jan Thies <jan.thies@haw-hamburg.de>
 */

#ifndef CYS_ATTEST_H
#define CYS_ATTEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "CYS/common.h"
#include "CYS/sealed_key.h"

/**
 * @brief   Build a signed attestation token in the secure world.
 *
 * @param[in]   key         sealed attestation key
 * @param[in]   nonce       verifier challenge
 * @param[in]   nonce_len   length of @p nonce
 * @param[out]  token       buffer for the token
 * @param[in]   token_size  size of @p token
 * @param[out]  token_len   number of bytes written to @p token
 *
 * @return  CYS_SUCCESS, or an error from the secure world
 */
CYS_error_t CYS_attest_get_token(const CYS_PROT_ecc_p256_key_t *key,
                                 const uint8_t *nonce, size_t nonce_len,
                                 uint8_t *token, size_t token_size,
                                 size_t *token_len);

#ifdef __cplusplus
}
#endif

#endif /* CYS_ATTEST_H */
