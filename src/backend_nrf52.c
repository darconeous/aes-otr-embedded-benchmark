#include "otr128.h"

#if defined(OTR128_PLATFORM_NRF52) || defined(CONFIG_SOC_NRF52840) || defined(NRF52840_XXAA)

#include <string.h>

#include <hal/nrf_ecb.h>

typedef struct nrf52_ecb_data {
    uint8_t key[OTR128_KEY_SIZE];
    uint8_t cleartext[OTR128_BLOCK_SIZE];
    uint8_t ciphertext[OTR128_BLOCK_SIZE];
} nrf52_ecb_data;

typedef struct nrf52_backend_state {
    nrf52_ecb_data ecb_data;
    uint8_t data_ptr_bound;
} nrf52_backend_state;

_Static_assert(sizeof(nrf52_backend_state) <= OTR128_BACKEND_STATE_BYTES,
               "nrf52 backend state exceeds OTR128_BACKEND_STATE_BYTES");

static int nrf52_set_encrypt_key(void *state, const uint8_t key[OTR128_KEY_SIZE]) {
    nrf52_backend_state *ctx = (nrf52_backend_state *)state;
    memcpy(ctx->ecb_data.key, key, OTR128_KEY_SIZE);
    return OTR128_OK;
}

static int nrf52_begin_message(void *state) {
    nrf52_backend_state *ctx = (nrf52_backend_state *)state;

    nrf_ecb_data_pointer_set(NRF_ECB, &ctx->ecb_data);
    ctx->data_ptr_bound = 1u;
    return OTR128_OK;
}

static int nrf52_encrypt_block(const void *state,
                               const uint8_t in[OTR128_BLOCK_SIZE],
                               uint8_t out[OTR128_BLOCK_SIZE]) {
    const nrf52_backend_state *ctx = (const nrf52_backend_state *)state;
    nrf52_backend_state *mutable_ctx = (nrf52_backend_state *)ctx;

    if (!mutable_ctx->data_ptr_bound) {
        nrf_ecb_data_pointer_set(NRF_ECB, &mutable_ctx->ecb_data);
        mutable_ctx->data_ptr_bound = 1u;
    }
    memcpy(mutable_ctx->ecb_data.cleartext, in, OTR128_BLOCK_SIZE);
    nrf_ecb_event_clear(NRF_ECB, NRF_ECB_EVENT_ENDECB);
    nrf_ecb_event_clear(NRF_ECB, NRF_ECB_EVENT_ERRORECB);
    nrf_ecb_task_trigger(NRF_ECB, NRF_ECB_TASK_STARTECB);
    while (!(nrf_ecb_event_check(NRF_ECB, NRF_ECB_EVENT_ENDECB) ||
             nrf_ecb_event_check(NRF_ECB, NRF_ECB_EVENT_ERRORECB))) {
    }
    if (nrf_ecb_event_check(NRF_ECB, NRF_ECB_EVENT_ERRORECB)) {
        return OTR128_ERR_BACKEND;
    }
    memcpy(out, mutable_ctx->ecb_data.ciphertext, OTR128_BLOCK_SIZE);
    return OTR128_OK;
}

static void nrf52_end_message(void *state) {
    nrf52_backend_state *ctx = (nrf52_backend_state *)state;

    ctx->data_ptr_bound = 0u;
}

static void nrf52_clear(void *state) {
    memset(state, 0, sizeof(nrf52_backend_state));
}

static const otr128_backend_vtable k_vtable = {
    nrf52_set_encrypt_key,
    nrf52_begin_message,
    nrf52_encrypt_block,
    nrf52_end_message,
    nrf52_clear
};

static const otr128_backend k_backend = {
    "nrf52-hw",
    sizeof(nrf52_backend_state),
    &k_vtable
};

const otr128_backend *otr128_backend_nrf52(void) {
    return &k_backend;
}

#else
const otr128_backend *otr128_backend_nrf52(void) {
    return NULL;
}
#endif
