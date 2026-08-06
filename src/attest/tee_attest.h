/*
 * Copyright (C) 2026 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        tee_attest.h
 * @brief       Secure-world attestation operation.
 *
 * @author      Jan Thies <jan.thies@haw-hamburg.de>
 */

#ifndef TEE_ATTEST_H
#define TEE_ATTEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "CYS/common.h"
#include "tee_secure_io.h"

/**
 * @brief   Build a signed attestation token inside the secure world.
 *
 * Measures the non-secure firmware, encodes an EAT claim set and signs it as a
 * COSE_Sign1. Because the whole token is produced here, the non-secure world
 * cannot forge the measurement.
 *
 * in[0]   sealed attestation key (CYS_PROT_ecc_p256_key_t)
 * in[1]   nonce from the verifier
 * out[0]  buffer receiving the token
 * out[1]  size_t receiving the token length
 *
 * @return  CYS_SUCCESS, or an error from measuring, encoding or signing
 */
CYS_error_t tee_attest_get_token(io_pack_in_t *in, size_t in_len,
                                 io_pack_out_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* TEE_ATTEST_H */
