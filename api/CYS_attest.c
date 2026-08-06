/*
 * Copyright (C) 2026 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        CYS_attest.c
 * @brief       Non-secure entry for the secure-world attestation operation.
 *
 * @author      Jan Thies <jan.thies@haw-hamburg.de>
 */

#include "CYS/common.h"
#include "CYS/os_mutex.h"
#include "CYS/sealed_key.h"
#include "tee_secure_io.h"
#include "tee_operations.h"

#include "CYS_attest.h"

CYS_error_t CYS_attest_get_token(const CYS_PROT_ecc_p256_key_t *key,
                                 const uint8_t *nonce, size_t nonce_len,
                                 uint8_t *token, size_t token_size,
                                 size_t *token_len)
{
    io_pack_in_t in[2] = {
        { .data = key, .len = sizeof(CYS_PROT_ecc_p256_key_t) },
        { .data = nonce, .len = nonce_len }
    };

    io_pack_out_t out[2] = {
        { .data = token, .len = token_size },
        { .data = token_len, .len = sizeof(*token_len) }
    };

    io_operation_info_t info = {
        .operation = TEE_ATTEST_GET_TOKEN,
        .in_len = sizeof(in)/sizeof(io_pack_in_t),
        .out_len = sizeof(out)/sizeof(io_pack_out_t)
    };

    while (os_get_mutex() != CYS_SUCCESS) {};
    CYS_error_t status = tee_secure_entry(&info, in, out);
    os_release_mutex();

    return status;
}
