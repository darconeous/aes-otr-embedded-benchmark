#ifndef OTR128_BACKEND_H
#define OTR128_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OTR128_BLOCK_SIZE 16u
#define OTR128_KEY_SIZE 16u
#define OTR128_TAG_MIN 4u
#define OTR128_TAG_MAX 16u
#define OTR128_NONCE_MIN 1u
#define OTR128_NONCE_MAX 15u
#define OTR128_BACKEND_STATE_BYTES 256u

struct otr128_backend_vtable;

typedef struct otr128_backend {
    const char *name;
    size_t state_size;
    const struct otr128_backend_vtable *vtable;
} otr128_backend;

typedef struct otr128_backend_vtable {
    int (*set_encrypt_key)(void *state, const uint8_t key[OTR128_KEY_SIZE]);
    int (*begin_message)(void *state);
    int (*encrypt_block)(const void *state,
                         const uint8_t in[OTR128_BLOCK_SIZE],
                         uint8_t out[OTR128_BLOCK_SIZE]);
    void (*end_message)(void *state);
    void (*clear)(void *state);
} otr128_backend_vtable;

const otr128_backend *otr128_backend_soft(void);
const otr128_backend *otr128_backend_esp32(void);
const otr128_backend *otr128_backend_nrf52(void);
const otr128_backend *otr128_backend_stm32u5(void);

#ifdef __cplusplus
}
#endif

#endif
