#ifndef OTR128_H
#define OTR128_H

#include "otr128_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    OTR128_OK = 0,
    OTR128_ERR_PARAM = -1,
    OTR128_ERR_BACKEND = -2,
    OTR128_ERR_AUTH = -3
};

typedef struct otr128_ctx {
    const otr128_backend *backend;
    uint8_t backend_state[OTR128_BACKEND_STATE_BYTES];
    uint8_t q_l[OTR128_BLOCK_SIZE];
    uint64_t block_encrypt_count;
    int initialized;
} otr128_ctx;

int otr128_init(otr128_ctx *ctx,
                const otr128_backend *backend,
                const uint8_t key[OTR128_KEY_SIZE]);

void otr128_clear(otr128_ctx *ctx);

int otr128_seal(otr128_ctx *ctx,
                const uint8_t *nonce,
                size_t nonce_len,
                const uint8_t *ad,
                size_t ad_len,
                const uint8_t *pt,
                size_t pt_len,
                uint8_t *ct,
                uint8_t *tag,
                size_t tag_len);

int otr128_open(otr128_ctx *ctx,
                const uint8_t *nonce,
                size_t nonce_len,
                const uint8_t *ad,
                size_t ad_len,
                const uint8_t *ct,
                size_t ct_len,
                const uint8_t *tag,
                size_t tag_len,
                uint8_t *pt);

int otr128_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

uint64_t otr128_get_block_encrypt_count(const otr128_ctx *ctx);
void otr128_reset_block_encrypt_count(otr128_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
