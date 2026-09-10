#include "ocb.h"
#include "random.h"
#include "CYS/common.h"
#include "CYS/sealed_key.h"
#include "cc310_registers.h"

#include "tee_rot.h"

#define TEE_ROT_AES_128_KEY_BYTES   (16)

/* This is for testing only! Ideally key should be set by an immutable bootloader or at least randomly generated! */
static const uint8_t AES_TEST_KEY[TEE_ROT_AES_128_KEY_BYTES] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

CYS_error_t tee_rot_try_generate_aes_key(void)
{
    if (TEE_CC_HOST_RGF->HOST_IOT_KDR0) {
        return CYS_ERROR_ALREADY_EXISTS;
    }

    /* This is for testing only! Ideally key should be set by an immutable bootloader or at least randomly generated! */
    TEE_CC_HOST_RGF->HOST_IOT_KDR0 = ((uint32_t *)AES_TEST_KEY)[0];
    TEE_CC_HOST_RGF->HOST_IOT_KDR1 = ((uint32_t *)AES_TEST_KEY)[1];
    TEE_CC_HOST_RGF->HOST_IOT_KDR2 = ((uint32_t *)AES_TEST_KEY)[2];
    TEE_CC_HOST_RGF->HOST_IOT_KDR3 = ((uint32_t *)AES_TEST_KEY)[3];

    if (TEE_CC_HOST_RGF->HOST_IOT_KDR0) {
        return CYS_SUCCESS;
    }

    return CYS_ERROR_GENERIC_ERROR;
}

/* The purpose travels as associated data. OCB authenticates it without storing
 * it, so unsealing only succeeds when the caller names the same purpose the key
 * was sealed for. */
CYS_error_t tee_rot_encrypt_key_ocb(CYS_PROT_purpose_t purpose, uint8_t *key_in, CYS_PROT_ecc_p256_key_t *sealed_key)
{
    cipher_t cipher = { 0 };
    cipher.interface = CIPHER_AES;
    uint8_t aad = (uint8_t)purpose;

    /* The hardware driver ignores the cipher context, so no need to initialize */
    int32_t result = cipher_encrypt_ocb(&cipher, &aad, sizeof(aad), CYS_PROT_SEAL_TAG_SIZE, sealed_key->nonce, CYS_PROT_SEAL_NONCE_SIZE, key_in, CYS_PROT_ECC_P256_KEY_SIZE, sealed_key->private_key);

    if(result == CYS_PROT_ECC_P256_KEY_SIZE + CYS_PROT_SEAL_TAG_SIZE) {
        return CYS_SUCCESS;
    }

    return CYS_ERROR_GENERIC_ERROR;
}

CYS_error_t tee_rot_decrypt_key_ocb(CYS_PROT_purpose_t purpose, CYS_PROT_ecc_p256_key_t *sealed_key, uint8_t *key_out)
{
    cipher_t cipher = { 0 };
    cipher.interface = CIPHER_AES;
    uint8_t aad = (uint8_t)purpose;

    /* The hardware driver ignores the cipher context, so no need to initialize */
    int32_t result = cipher_decrypt_ocb(&cipher, &aad, sizeof(aad), CYS_PROT_SEAL_TAG_SIZE, sealed_key->nonce, CYS_PROT_SEAL_NONCE_SIZE, sealed_key->private_key, CYS_PROT_ECC_P256_KEY_SIZE+CYS_PROT_SEAL_TAG_SIZE, key_out);

    /* A blob that does not authenticate did not come from this device, or was
     * sealed for another purpose. Without this check the caller would work on
     * whatever the decryption left behind. */
    if (result != CYS_PROT_ECC_P256_KEY_SIZE) {
        return CYS_ERROR_CORRUPTION_DETECTED;
    }

    return CYS_SUCCESS;
}

