/*
 * Copyright (C) 2026 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        tee_attest.c
 * @brief       Measure the non-secure firmware and produce a signed EAT.
 *
 * The whole token (EAT claim set + COSE_Sign1) is built here so a compromised
 * non-secure world can neither forge the measurement nor the signature. The
 * byte layout matches the non-secure software backend, so the same verifier
 * accepts either.
 *
 * @author      Jan Thies <jan.thies@haw-hamburg.de>
 */

#include <stdint.h>
#include <stdbool.h>

#include "nanocbor/nanocbor.h"

#include "CYS/common.h"
#include "CYS/sealed_key.h"
#include "tee_secure_io.h"
#include "tee_io_sanitizer.h"

#include "tee_ecc.h"
#include "tee_hashes.h"
#include "tee_rot.h"

#include "nrf9160.h"
#include "nrf9160_bitfields.h"

#include "tee_attest.h"

/* Non-secure firmware extent. The secure world knows where the non-secure
 * flash starts (linker symbol) and measures it up to the end of flash, so the
 * non-secure side cannot narrow down what is measured. */
extern unsigned int FLASH_START_NS[];
#define FLASH_END                   (0x100000u)     /* nRF9160: 1 MiB of flash */

#define SHA256_LEN                  (32)
#define INSTANCE_ID_LEN             (1 + SHA256_LEN)

/* Scratch buffer for the token payload and the signed structure. */
#ifndef CONFIG_PSA_ATTEST_TOKEN_MAX_SIZE
#define CONFIG_PSA_ATTEST_TOKEN_MAX_SIZE    (512)
#endif

/* Device claims. Placeholders, matching the software backend. */

/* A profile derived from the PSA baseline, as RFC 9783 section 4.5.2.1
 * describes. Not TF-M, so it does not claim the TF-M identifier. */
#define ATTEST_PROFILE              "tag:psacertified.org,2023:psa#riot-tee"
/* Negative values denote a caller from the non-secure world, positive ones
 * a caller from the secure world (RFC 9783 section 4.1.2). */
#define ATTEST_CLIENT_ID            (-1)
#define ATTEST_LIFECYCLE            (0x3000u)        /* SECURED */

/* EAT claim keys (RFC 9711 and RFC 9783) */
#define EAT_NONCE                   10
#define EAT_UEID                    256
#define EAT_DBGSTAT                 263
#define EAT_PROFILE                 265
#define EAT_CLIENT_ID               2394
#define EAT_LIFECYCLE               2395
#define EAT_IMPLEMENTATION          2396
#define EAT_SW_COMPONENTS           2399
#define SW_COMPONENT_TYPE           1
#define SW_COMPONENT_MEASUREMENT    2
#define SW_COMPONENT_SIGNER_ID      5

/* dbgstat values (RFC 9711 section 4.2.9) */
#define DBGSTAT_ENABLED             0
#define DBGSTAT_DISABLED            1

/* COSE_Sign1 */
#define COSE_SIGN1_TAG              18
#define COSE_LABEL_ALG              1
#define COSE_ALG_ES256              (-7)

/* Implementation ID: identifies the hardware and firmware. Placeholder. */
static const uint8_t _impl_id[32] = { 0 };

/* Signer ID: identifies who signed a component. Nothing here is delivered
 * through a signed manifest, so this is a placeholder. */
static const uint8_t _signer_id[32] = { 0 };

/* One measured software component (an entry in the sw-components claim). */
typedef struct {
    const char *type;
    const uint8_t *measurement;
    size_t measurement_len;
} sw_component_t;

/* Encode the EAT claim set (the COSE payload). */
static int encode_claims(uint8_t *buf, size_t buf_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *instance_id, int dbgstat,
                         const sw_component_t *components, size_t num_components,
                         size_t *out_len)
{
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, buf_len);

    nanocbor_fmt_map(&enc, 8);

    nanocbor_fmt_int(&enc, EAT_NONCE);
    nanocbor_put_bstr(&enc, nonce, nonce_len);

    nanocbor_fmt_int(&enc, EAT_UEID);
    nanocbor_put_bstr(&enc, instance_id, INSTANCE_ID_LEN);

    nanocbor_fmt_int(&enc, EAT_DBGSTAT);
    nanocbor_fmt_int(&enc, dbgstat);

    nanocbor_fmt_int(&enc, EAT_PROFILE);
    nanocbor_put_tstr(&enc, ATTEST_PROFILE);

    nanocbor_fmt_int(&enc, EAT_CLIENT_ID);
    nanocbor_fmt_int(&enc, ATTEST_CLIENT_ID);

    nanocbor_fmt_int(&enc, EAT_LIFECYCLE);
    nanocbor_fmt_uint(&enc, ATTEST_LIFECYCLE);

    nanocbor_fmt_int(&enc, EAT_IMPLEMENTATION);
    nanocbor_put_bstr(&enc, _impl_id, sizeof(_impl_id));

    nanocbor_fmt_int(&enc, EAT_SW_COMPONENTS);
    nanocbor_fmt_array(&enc, num_components);
    for (size_t i = 0; i < num_components; i++) {
        nanocbor_fmt_map(&enc, 3);
        nanocbor_fmt_int(&enc, SW_COMPONENT_TYPE);
        nanocbor_put_tstr(&enc, components[i].type);
        nanocbor_fmt_int(&enc, SW_COMPONENT_MEASUREMENT);
        nanocbor_put_bstr(&enc, components[i].measurement,
                          components[i].measurement_len);
        nanocbor_fmt_int(&enc, SW_COMPONENT_SIGNER_ID);
        nanocbor_put_bstr(&enc, _signer_id, sizeof(_signer_id));
    }

    size_t needed = nanocbor_encoded_len(&enc);
    if (needed > buf_len) {
        return -1;
    }
    *out_len = needed;
    return 0;
}

/* Serialize the protected header { alg: ES256 }. */
static int encode_protected(uint8_t *buf, size_t buf_len, size_t *out_len)
{
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, buf_len);
    nanocbor_fmt_map(&enc, 1);
    nanocbor_fmt_int(&enc, COSE_LABEL_ALG);
    nanocbor_fmt_int(&enc, COSE_ALG_ES256);

    *out_len = nanocbor_encoded_len(&enc);
    return (*out_len <= buf_len) ? 0 : -1;
}

/* Build the COSE Sig_structure: the exact bytes that get hashed and signed. */
static int encode_to_be_signed(uint8_t *buf, size_t buf_len,
                               const uint8_t *prot, size_t prot_len,
                               const uint8_t *payload, size_t payload_len,
                               size_t *out_len)
{
    nanocbor_encoder_t enc;

    nanocbor_encoder_init(&enc, buf, buf_len);
    nanocbor_fmt_array(&enc, 4);
    nanocbor_put_tstr(&enc, "Signature1");
    nanocbor_put_bstr(&enc, prot, prot_len);
    nanocbor_put_bstr(&enc, (const uint8_t *)"", 0);    /* empty external_aad */
    nanocbor_put_bstr(&enc, payload, payload_len);

    *out_len = nanocbor_encoded_len(&enc);
    return (*out_len <= buf_len) ? 0 : -1;
}

/* Wrap the payload in a COSE_Sign1 and sign it with the unsealed key. */
static CYS_error_t sign_cose(const uint8_t *payload, size_t payload_len,
                             const uint8_t *priv,
                             uint8_t *out, size_t out_size, size_t *out_len)
{
    uint8_t tbs[CONFIG_PSA_ATTEST_TOKEN_MAX_SIZE];
    uint8_t prot[8];
    size_t prot_len, tbs_len;

    if (encode_protected(prot, sizeof(prot), &prot_len) != 0) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }
    if (encode_to_be_signed(tbs, sizeof(tbs), prot, prot_len,
                            payload, payload_len, &tbs_len) != 0) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    uint8_t digest[SHA256_LEN];
    CYS_error_t status = tee_sha256(tbs, tbs_len, digest);
    if (status != CYS_SUCCESS) {
        return status;
    }

    uint8_t sig[CYS_PROT_ECC_P256_SIG_SIZE];
    status = tee_ecc_p256_sign_digest(priv, CYS_PROT_ECC_P256_KEY_SIZE,
                                      digest, sizeof(digest), sig);
    if (status != CYS_SUCCESS) {
        return status;
    }

    /* COSE_Sign1: 18([ protected, {}, payload, signature ]) */
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, out, out_size);
    nanocbor_fmt_tag(&enc, COSE_SIGN1_TAG);
    nanocbor_fmt_array(&enc, 4);
    nanocbor_put_bstr(&enc, prot, prot_len);
    nanocbor_fmt_map(&enc, 0);                          /* unprotected header */
    nanocbor_put_bstr(&enc, payload, payload_len);
    nanocbor_put_bstr(&enc, sig, sizeof(sig));

    size_t needed = nanocbor_encoded_len(&enc);
    if (needed > out_size) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }
    *out_len = needed;
    return CYS_SUCCESS;
}

/* A measurement provider hashes one component. Providers run in the secure
 * world, so the non-secure side cannot influence what is measured. */
typedef struct {
    const char *type;
    CYS_error_t (*measure)(uint8_t *out, size_t out_size, size_t *out_len);
} tee_attest_provider_t;

/* Firmware provider: hash the whole non-secure flash image. */
static CYS_error_t measure_firmware(uint8_t *out, size_t out_size,
                                    size_t *out_len)
{
    if (out_size < SHA256_LEN) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }
    CYS_error_t status = tee_sha256((const uint8_t *)FLASH_START_NS,
                                    FLASH_END - (uintptr_t)FLASH_START_NS, out);
    if (status == CYS_SUCCESS) {
        *out_len = SHA256_LEN;
    }
    return status;
}

static const tee_attest_provider_t _providers[] = {
    { .type = "firmware", .measure = measure_firmware },
};

#define NUM_PROVIDERS   (sizeof(_providers) / sizeof(_providers[0]))

/* Run every provider, filling one software component each. */
static CYS_error_t collect_measurements(sw_component_t *comps, uint8_t *scratch,
                                        size_t scratch_size, size_t *out_count)
{
    size_t used = 0;
    for (size_t i = 0; i < NUM_PROVIDERS; i++) {
        size_t len;
        CYS_error_t status = _providers[i].measure(scratch + used,
                                                   scratch_size - used, &len);
        if (status != CYS_SUCCESS) {
            return status;
        }
        comps[i].type = _providers[i].type;
        comps[i].measurement = scratch + used;
        comps[i].measurement_len = len;
        used += len;
    }
    *out_count = NUM_PROVIDERS;
    return CYS_SUCCESS;
}

/* Report the debug-port lock state as an RFC 9711 dbgstat value. APPROTECT and
 * SECUREAPPROTECT gate debugger access; if either leaves it open, debug is
 * effectively enabled. Read from the secure UICR alias. */
static int debug_status(void)
{
    bool ns_open = (NRF_UICR_S->APPROTECT == UICR_APPROTECT_PALL_Unprotected);
    bool s_open = (NRF_UICR_S->SECUREAPPROTECT == UICR_SECUREAPPROTECT_PALL_Unprotected);

    return (ns_open || s_open) ? DBGSTAT_ENABLED : DBGSTAT_DISABLED;
}

CYS_error_t tee_attest_get_token(io_pack_in_t *in, size_t in_len,
                                 io_pack_out_t *out, size_t out_len)
{
    if (in_len != 2 || out_len != 2) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    CYS_PROT_ecc_p256_key_t *sealed =
        cmse_check_address_range((void *)in[0].data, in[0].len, CMSE_NONSECURE);
    uint8_t *nonce = cmse_check_address_range((void *)in[1].data, in[1].len, CMSE_NONSECURE);
    uint8_t *token = cmse_check_address_range(out[0].data, out[0].len, CMSE_NONSECURE);
    size_t *token_len = cmse_check_address_range(out[1].data, out[1].len, CMSE_NONSECURE);

    if (sealed == NULL || nonce == NULL || token == NULL || token_len == NULL) {
        return CYS_ERROR_CORRUPTION_DETECTED;
    }
    if (in[0].len != sizeof(CYS_PROT_ecc_p256_key_t) ||
        out[1].len != sizeof(size_t)) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    size_t nonce_len = in[1].len;

    /* 1. measure via the providers (firmware, ...) */
    sw_component_t components[NUM_PROVIDERS];
    uint8_t scratch[NUM_PROVIDERS * SHA256_LEN];
    size_t num_components;
    CYS_error_t status = collect_measurements(components, scratch,
                                              sizeof(scratch), &num_components);
    if (status != CYS_SUCCESS) {
        return status;
    }

    /* 2. unseal the attestation key and derive its public key */
    uint8_t priv[CYS_PROT_ECC_P256_KEY_SIZE];
    status = tee_rot_decrypt_key_ocb(sealed, priv);
    if (status != CYS_SUCCESS) {
        return status;
    }

    uint8_t pubkey[CYS_PROT_ECC_P256_PUB_SIZE];
    status = tee_ecc_p256_derive_pubkey(priv, sizeof(priv), pubkey, sizeof(pubkey));
    if (status != CYS_SUCCESS) {
        return status;
    }

    /* 3. instance ID = 0x01 || SHA-256(public key) */
    uint8_t instance_id[INSTANCE_ID_LEN];
    instance_id[0] = 0x01;
    status = tee_sha256(pubkey, sizeof(pubkey), instance_id + 1);
    if (status != CYS_SUCCESS) {
        return status;
    }

    /* 4. encode the EAT claim set */
    uint8_t payload[CONFIG_PSA_ATTEST_TOKEN_MAX_SIZE];
    size_t payload_len;
    if (encode_claims(payload, sizeof(payload), nonce, nonce_len,
                      instance_id, debug_status(), components, num_components,
                      &payload_len) != 0) {
        return CYS_ERROR_INVALID_ARGUMENT;
    }

    /* 5. sign it as a COSE_Sign1 */
    return sign_cose(payload, payload_len, priv, token, out[0].len, token_len);
}
