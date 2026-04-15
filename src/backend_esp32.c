#include "otr128.h"

#if defined(ESP_PLATFORM)

#include <aes/esp_aes.h>
#include <esp_private/periph_ctrl.h>
#include <hal/aes_hal.h>
#include <hal/aes_types.h>
#include <soc/periph_defs.h>
#include <string.h>

typedef struct esp32_backend_state {
    uint8_t key[OTR128_KEY_SIZE];
    uint8_t message_active;
} esp32_backend_state;

static int esp32_set_encrypt_key(void *state, const uint8_t key[OTR128_KEY_SIZE]) {
    esp32_backend_state *ctx = (esp32_backend_state *)state;
    memcpy(ctx->key, key, OTR128_KEY_SIZE);
    return OTR128_OK;
}

static int esp32_begin_message(void *state) {
    esp32_backend_state *ctx = (esp32_backend_state *)state;

    if (ctx->message_active) {
        return OTR128_OK;
    }
    esp_aes_acquire_hardware();
    if (aes_hal_setkey(ctx->key, OTR128_KEY_SIZE, ESP_AES_ENCRYPT) != OTR128_KEY_SIZE) {
        esp_aes_release_hardware();
        return OTR128_ERR_BACKEND;
    }
    ctx->message_active = 1u;
    return OTR128_OK;
}

static int esp32_encrypt_block(const void *state,
                               const uint8_t in[OTR128_BLOCK_SIZE],
                               uint8_t out[OTR128_BLOCK_SIZE]) {
    esp32_backend_state *ctx = (esp32_backend_state *)state;

    if (!ctx->message_active) {
        if (esp32_begin_message(ctx) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        aes_hal_transform_block(in, out);
        esp_aes_release_hardware();
        ctx->message_active = 0u;
        return OTR128_OK;
    }
    aes_hal_transform_block(in, out);
    return OTR128_OK;
}

static void esp32_end_message(void *state) {
    esp32_backend_state *ctx = (esp32_backend_state *)state;

    if (ctx->message_active) {
        esp_aes_release_hardware();
        ctx->message_active = 0u;
    }
}

static void esp32_clear(void *state) {
    esp32_end_message(state);
    memset(state, 0, sizeof(esp32_backend_state));
}

static const otr128_backend_vtable k_vtable = {
    esp32_set_encrypt_key,
    esp32_begin_message,
    esp32_encrypt_block,
    esp32_end_message,
    esp32_clear
};

static const otr128_backend k_backend = {
    "esp32-hw",
    sizeof(esp32_backend_state),
    &k_vtable
};

const otr128_backend *otr128_backend_esp32(void) {
    return &k_backend;
}

#else
const otr128_backend *otr128_backend_esp32(void) {
    return NULL;
}
#endif
