/*
 * Copyright (C) 2024 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        tee_hashes.c
 * @brief
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 */

#include <string.h>

#include "CYS/common.h"
#include "CYS/unprotected.h"

#include "cc3xx_hash.h"

#include "tee_secure_io.h"
#include "tee_io_sanitizer.h"
#include "tee_crypto_common.h"

/* The CC310 DMA engine can not read from flash, only from RAM. Nordic states this
 * in the CRYPTOCELL chapter of the nRF9160 product specification: data held in a
 * memory that the DMA can not reach has to be copied into SRAM first. Callers may
 * hand in any non-secure address, including the firmware image in flash, so every
 * input is passed through a bounce buffer. The chunk size trades secure RAM
 * against the number of DMA transfers. */
#define SHA256_LEN          (32)
#define TEE_HASH_MAX_CHUNK  (0x1000)
static uint8_t _hash_bounce[TEE_HASH_MAX_CHUNK];

static cc3xx_err_t hash_update_bounced(const uint8_t *data, size_t len)
{
    cc3xx_err_t status = CC3XX_ERR_SUCCESS;

    while (len > 0 && status == CC3XX_ERR_SUCCESS) {
        size_t chunk = (len < TEE_HASH_MAX_CHUNK) ? len : TEE_HASH_MAX_CHUNK;

        memcpy(_hash_bounce, data, chunk);
        status = cc3xx_lowlevel_hash_update(_hash_bounce, chunk);
        data += chunk;
        len -= chunk;
    }
    return status;
}

CYS_error_t tee_hash_sha256_setup(io_pack_in_t *in, size_t in_len, io_pack_out_t *out, size_t out_len)
{
    if (out_len != 1) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    CYS_hash_sha256_ctx_t *ctx = cmse_check_address_range(out[0].data, out[0].len, CMSE_NONSECURE);

    if (ctx == NULL) {
        return CYS_ERROR_CORRUPTION_DETECTED;
    }

    NRF_CRYPTOCELL->ENABLE = 1;

    cc3xx_err_t status = cc3xx_lowlevel_hash_init(CC3XX_HASH_ALG_SHA256);
    if (status != CC3XX_ERR_SUCCESS) {
        goto exit;
    }

    cc3xx_lowlevel_hash_get_state((struct cc3xx_hash_state_t *)ctx->data);
    cc3xx_lowlevel_hash_uninit();

exit:
    (void) in;
    (void) in_len;
    NRF_CRYPTOCELL->ENABLE = 0;
    return tee_map_error_values(status);
}

CYS_error_t tee_hash_sha256_update(io_pack_in_t *in, size_t in_len, io_pack_out_t *out, size_t out_len)
{
    if (in_len != 2) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    CYS_hash_sha256_ctx_t *ctx = cmse_check_address_range((void *)in[0].data, in[0].len, CMSE_NONSECURE);
    uint8_t *input = cmse_check_address_range((void *)in[1].data, in[1].len, CMSE_NONSECURE);

    if (ctx == NULL || input == NULL) {
        return CYS_ERROR_CORRUPTION_DETECTED;
    }

    size_t input_size = in[1].len;

    NRF_CRYPTOCELL->ENABLE = 1;

    cc3xx_lowlevel_hash_set_state((struct cc3xx_hash_state_t *)ctx->data);

    cc3xx_err_t status = hash_update_bounced(input, input_size);
    if (status != CC3XX_ERR_SUCCESS) {
        goto exit;
    }

    cc3xx_lowlevel_hash_get_state((struct cc3xx_hash_state_t *)ctx->data);
    cc3xx_lowlevel_hash_uninit();

exit:
    (void) out;
    (void) out_len;
    NRF_CRYPTOCELL->ENABLE = 0;
    return tee_map_error_values(status);
}

CYS_error_t tee_hash_sha256_finish(io_pack_in_t *in, size_t in_len, io_pack_out_t *out, size_t out_len)
{
    if (in_len != 1 || out_len != 1)
    {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    CYS_hash_sha256_ctx_t *ctx = cmse_check_address_range((void *)in[0].data, in[0].len, CMSE_NONSECURE);
    uint8_t *digest = cmse_check_address_range(out[0].data, out[0].len, CMSE_NONSECURE);

    if (ctx == NULL || digest == NULL) {
        return CYS_ERROR_CORRUPTION_DETECTED;
    }

    /* The driver writes the result as 32 bit words and asserts that the target
     * is word aligned, and it writes as many words as the length allows. A
     * non-secure caller may hand in any address and any buffer size, and the
     * PSA API puts no alignment requirement on the digest buffer, so the result
     * is taken into an aligned local of exactly one digest and copied out. */
    uint32_t result[SHA256_LEN / sizeof(uint32_t)];

    if (out[0].len < sizeof(result)) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    NRF_CRYPTOCELL->ENABLE = 1;

    cc3xx_lowlevel_hash_set_state((struct cc3xx_hash_state_t *)ctx->data);
    cc3xx_lowlevel_hash_finish(result, sizeof(result));
    memcpy(digest, result, sizeof(result));

    NRF_CRYPTOCELL->ENABLE = 0;

    return CYS_SUCCESS;
}

CYS_error_t tee_sha256(const uint8_t *data, size_t len, uint8_t *digest)
{
    uint32_t out[8];        /* 32 bytes, aligned for the DMA engine */

    NRF_CRYPTOCELL->ENABLE = 1;

    cc3xx_err_t status = cc3xx_lowlevel_hash_init(CC3XX_HASH_ALG_SHA256);
    if (status == CC3XX_ERR_SUCCESS) {
        status = hash_update_bounced(data, len);
        if (status == CC3XX_ERR_SUCCESS) {
            cc3xx_lowlevel_hash_finish(out, sizeof(out));
            memcpy(digest, out, sizeof(out));
        }
        cc3xx_lowlevel_hash_uninit();
    }

    NRF_CRYPTOCELL->ENABLE = 0;
    return tee_map_error_values(status);
}
