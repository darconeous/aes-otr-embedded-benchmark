#include "otr128.h"

#if defined(OTR128_PLATFORM_STM32U5) || defined(STM32U5xx)

#include <string.h>
#include "stm32u5xx_hal.h"
#include "stm32u5xx_hal_cryp.h"

typedef struct stm32u5_backend_state {
    CRYP_HandleTypeDef hcryp;
    uint32_t key_words[4];
} stm32u5_backend_state;

_Static_assert(sizeof(stm32u5_backend_state) <= OTR128_BACKEND_STATE_BYTES,
               "stm32u5 backend state exceeds OTR128_BACKEND_STATE_BYTES");

static int stm32u5_set_encrypt_key(void *state, const uint8_t key[OTR128_KEY_SIZE]) {
    stm32u5_backend_state *ctx = (stm32u5_backend_state *)state;
    size_t i;

    memset(ctx, 0, sizeof(*ctx));
    for (i = 0; i < 4; ++i) {
        ctx->key_words[i] = ((uint32_t)key[i * 4] << 24) |
                            ((uint32_t)key[i * 4 + 1] << 16) |
                            ((uint32_t)key[i * 4 + 2] << 8) |
                            (uint32_t)key[i * 4 + 3];
    }

    ctx->hcryp.Instance = AES;
    ctx->hcryp.Init.DataType = CRYP_DATATYPE_8B;
    ctx->hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
    ctx->hcryp.Init.Algorithm = CRYP_AES_ECB;
    ctx->hcryp.Init.pKey = ctx->key_words;

    if (HAL_CRYP_Init(&ctx->hcryp) != HAL_OK) {
        return OTR128_ERR_BACKEND;
    }
    return OTR128_OK;
}

static int stm32u5_encrypt_block(const void *state,
                                 const uint8_t in[OTR128_BLOCK_SIZE],
                                 uint8_t out[OTR128_BLOCK_SIZE]) {
    const stm32u5_backend_state *ctx = (const stm32u5_backend_state *)state;
    uint32_t input_words[4];
    uint32_t output_words[4];
    size_t i;

    for (i = 0; i < 4; ++i) {
        input_words[i] = ((uint32_t)in[i * 4] << 24) |
                         ((uint32_t)in[i * 4 + 1] << 16) |
                         ((uint32_t)in[i * 4 + 2] << 8) |
                         (uint32_t)in[i * 4 + 3];
    }
    if (HAL_CRYP_Encrypt((CRYP_HandleTypeDef *)&ctx->hcryp, input_words, 4u, output_words, HAL_MAX_DELAY) != HAL_OK) {
        return OTR128_ERR_BACKEND;
    }
    for (i = 0; i < 4; ++i) {
        out[i * 4] = (uint8_t)(output_words[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(output_words[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(output_words[i] >> 8);
        out[i * 4 + 3] = (uint8_t)output_words[i];
    }
    return OTR128_OK;
}

static void stm32u5_clear(void *state) {
    stm32u5_backend_state *ctx = (stm32u5_backend_state *)state;
    HAL_CRYP_DeInit(&ctx->hcryp);
    memset(ctx, 0, sizeof(*ctx));
}

static const otr128_backend_vtable k_vtable = {
    stm32u5_set_encrypt_key,
    NULL,
    stm32u5_encrypt_block,
    NULL,
    stm32u5_clear
};

static const otr128_backend k_backend = {
    "stm32u5-hw",
    sizeof(stm32u5_backend_state),
    &k_vtable
};

const otr128_backend *otr128_backend_stm32u5(void) {
    return &k_backend;
}

#else
const otr128_backend *otr128_backend_stm32u5(void) {
    return NULL;
}
#endif
