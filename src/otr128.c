#include "otr128.h"

#include <string.h>

static void xor_block(uint8_t out[OTR128_BLOCK_SIZE],
                      const uint8_t a[OTR128_BLOCK_SIZE],
                      const uint8_t b[OTR128_BLOCK_SIZE]) {
    size_t i;
    for (i = 0; i < OTR128_BLOCK_SIZE; ++i) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void xor_block_inplace(uint8_t acc[OTR128_BLOCK_SIZE],
                              const uint8_t block[OTR128_BLOCK_SIZE]) {
    size_t i;
    for (i = 0; i < OTR128_BLOCK_SIZE; ++i) {
        acc[i] ^= block[i];
    }
}

static void copy_pad10(uint8_t out[OTR128_BLOCK_SIZE], const uint8_t *in, size_t len) {
    memset(out, 0, OTR128_BLOCK_SIZE);
    if (len > 0u) {
        memcpy(out, in, len);
    }
    if (len < OTR128_BLOCK_SIZE) {
        out[len] = 0x80u;
    }
}

static void gf_double(const uint8_t in[OTR128_BLOCK_SIZE], uint8_t out[OTR128_BLOCK_SIZE]) {
    uint8_t carry = (uint8_t)(in[0] >> 7);
    size_t i;

    for (i = 0; i < OTR128_BLOCK_SIZE - 1u; ++i) {
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    }
    out[OTR128_BLOCK_SIZE - 1u] = (uint8_t)(in[OTR128_BLOCK_SIZE - 1u] << 1);
    if (carry != 0u) {
        out[OTR128_BLOCK_SIZE - 1u] ^= 0x87u;
    }
}

static void gf_triple(const uint8_t in[OTR128_BLOCK_SIZE], uint8_t out[OTR128_BLOCK_SIZE]) {
    uint8_t doubled[OTR128_BLOCK_SIZE];
    gf_double(in, doubled);
    xor_block(out, in, doubled);
}

static int encrypt_block(const otr128_ctx *ctx,
                         const uint8_t in[OTR128_BLOCK_SIZE],
                         uint8_t out[OTR128_BLOCK_SIZE]) {
    int rc = ctx->backend->vtable->encrypt_block(ctx->backend_state, in, out);
    if (rc == OTR128_OK) {
        ((otr128_ctx *)ctx)->block_encrypt_count++;
    }
    return rc;
}

static int begin_message(otr128_ctx *ctx) {
    if (ctx->backend->vtable->begin_message != NULL) {
        return ctx->backend->vtable->begin_message(ctx->backend_state);
    }
    return OTR128_OK;
}

static void end_message(otr128_ctx *ctx) {
    if (ctx->backend->vtable->end_message != NULL) {
        ctx->backend->vtable->end_message(ctx->backend_state);
    }
}

static void format_nonce(size_t tag_len,
                         const uint8_t *nonce,
                         size_t nonce_len,
                         uint8_t out[OTR128_BLOCK_SIZE]) {
    memset(out, 0, OTR128_BLOCK_SIZE);
    memcpy(&out[OTR128_BLOCK_SIZE - nonce_len], nonce, nonce_len);
    out[0] = (uint8_t)(((tag_len * 8u) % 128u) << 1);
    out[OTR128_BLOCK_SIZE - nonce_len - 1u] |= 0x01u;
}

static int compute_serial_ad_tag(otr128_ctx *ctx,
                                 const uint8_t *ad,
                                 size_t ad_len,
                                 uint8_t out[OTR128_BLOCK_SIZE]) {
    uint8_t xi[OTR128_BLOCK_SIZE];
    uint8_t block[OTR128_BLOCK_SIZE];
    size_t offset = 0u;

    memset(xi, 0, sizeof(xi));
    if (ad_len == 0u) {
        memset(out, 0, OTR128_BLOCK_SIZE);
        return OTR128_OK;
    }

    while ((ad_len - offset) > OTR128_BLOCK_SIZE) {
        xor_block(block, &ad[offset], xi);
        if (encrypt_block(ctx, block, xi) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        offset += OTR128_BLOCK_SIZE;
    }

    copy_pad10(block, &ad[offset], ad_len - offset);
    xor_block_inplace(xi, block);
    if ((ad_len - offset) == OTR128_BLOCK_SIZE) {
        gf_double(ctx->q_l, block);
        gf_double(block, block);
    } else {
        gf_double(ctx->q_l, block);
    }
    xor_block(block, block, xi);
    return encrypt_block(ctx, block, out);
}

static int process_nonce(const otr128_ctx *ctx,
                         size_t tag_len,
                         const uint8_t *nonce,
                         size_t nonce_len,
                         const uint8_t ta[OTR128_BLOCK_SIZE],
                         uint8_t u[OTR128_BLOCK_SIZE]) {
    uint8_t formatted[OTR128_BLOCK_SIZE];
    uint8_t l0[OTR128_BLOCK_SIZE];

    format_nonce(tag_len, nonce, nonce_len, formatted);
    if (encrypt_block(ctx, formatted, l0) != OTR128_OK) {
        return OTR128_ERR_BACKEND;
    }
    xor_block(l0, l0, ta);
    gf_double(l0, u);
    return OTR128_OK;
}

static int ef_serial(otr128_ctx *ctx,
                     const uint8_t *pt,
                     size_t pt_len,
                     const uint8_t u[OTR128_BLOCK_SIZE],
                     uint8_t *ct,
                     uint8_t te[OTR128_BLOCK_SIZE]) {
    uint8_t sum[OTR128_BLOCK_SIZE];
    uint8_t l[OTR128_BLOCK_SIZE];
    uint8_t ls[OTR128_BLOCK_SIZE];
    uint8_t tmp[OTR128_BLOCK_SIZE];
    uint8_t z[OTR128_BLOCK_SIZE];
    uint8_t last_block[OTR128_BLOCK_SIZE];
    uint8_t last_mask[OTR128_BLOCK_SIZE];
    size_t ell = 0u;
    size_t last = 0u;
    size_t i;

    memset(sum, 0, sizeof(sum));
    memcpy(l, u, OTR128_BLOCK_SIZE);
    gf_triple(u, ls);

    if (pt_len != 0u) {
        last = pt_len % (2u * OTR128_BLOCK_SIZE);
        if (last == 0u) {
            last = 2u * OTR128_BLOCK_SIZE;
        }
        ell = (pt_len - last) / (2u * OTR128_BLOCK_SIZE);
    }

    for (i = 0; i < ell; ++i) {
        const uint8_t *m0 = &pt[i * 32u];
        const uint8_t *m1 = &pt[i * 32u + OTR128_BLOCK_SIZE];
        uint8_t *c0 = &ct[i * 32u];
        uint8_t *c1 = &ct[i * 32u + OTR128_BLOCK_SIZE];

        xor_block(tmp, l, m0);
        if (encrypt_block(ctx, tmp, tmp) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        xor_block(c0, tmp, m1);
        xor_block(tmp, ls, c0);
        if (encrypt_block(ctx, tmp, tmp) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        xor_block(c1, tmp, m0);
        xor_block_inplace(sum, m1);
        xor_block(l, l, ls);
        gf_double(ls, ls);
    }

    if (last <= OTR128_BLOCK_SIZE) {
        if (encrypt_block(ctx, l, z) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        for (i = 0; i < last; ++i) {
            ct[ell * 32u + i] = (uint8_t)(z[i] ^ pt[ell * 32u + i]);
        }
        copy_pad10(last_block, &pt[ell * 32u], last);
        xor_block_inplace(sum, last_block);
        memcpy(last_mask, l, OTR128_BLOCK_SIZE);
    } else {
        const uint8_t *m0 = &pt[ell * 32u];
        const uint8_t *m1 = &pt[ell * 32u + OTR128_BLOCK_SIZE];
        uint8_t *c0 = &ct[ell * 32u];
        uint8_t *c1 = &ct[ell * 32u + OTR128_BLOCK_SIZE];
        size_t tail = last - OTR128_BLOCK_SIZE;

        xor_block(tmp, l, m0);
        if (encrypt_block(ctx, tmp, z) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        for (i = 0; i < tail; ++i) {
            c1[i] = (uint8_t)(z[i] ^ m1[i]);
        }
        copy_pad10(last_block, c1, tail);
        xor_block_inplace(sum, z);
        xor_block_inplace(sum, last_block);
        xor_block(tmp, ls, last_block);
        if (encrypt_block(ctx, tmp, tmp) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        xor_block(c0, tmp, m0);
        memcpy(last_mask, ls, OTR128_BLOCK_SIZE);
    }

    gf_double(last_mask, tmp);
    if ((last == OTR128_BLOCK_SIZE) || (last == 2u * OTR128_BLOCK_SIZE)) {
        gf_triple(tmp, tmp);
    } else {
        gf_double(tmp, tmp);
    }
    xor_block(last_mask, last_mask, tmp);
    xor_block(sum, sum, last_mask);
    return encrypt_block(ctx, sum, te);
}

static int df_serial(otr128_ctx *ctx,
                     const uint8_t *ct,
                     size_t ct_len,
                     const uint8_t u[OTR128_BLOCK_SIZE],
                     uint8_t *pt,
                     uint8_t te[OTR128_BLOCK_SIZE]) {
    uint8_t sum[OTR128_BLOCK_SIZE];
    uint8_t l[OTR128_BLOCK_SIZE];
    uint8_t ls[OTR128_BLOCK_SIZE];
    uint8_t tmp[OTR128_BLOCK_SIZE];
    uint8_t z[OTR128_BLOCK_SIZE];
    uint8_t last_block[OTR128_BLOCK_SIZE];
    uint8_t last_mask[OTR128_BLOCK_SIZE];
    size_t ell = 0u;
    size_t last = 0u;
    size_t i;

    memset(sum, 0, sizeof(sum));
    memcpy(l, u, OTR128_BLOCK_SIZE);
    gf_triple(u, ls);

    if (ct_len != 0u) {
        last = ct_len % (2u * OTR128_BLOCK_SIZE);
        if (last == 0u) {
            last = 2u * OTR128_BLOCK_SIZE;
        }
        ell = (ct_len - last) / (2u * OTR128_BLOCK_SIZE);
    }

    for (i = 0; i < ell; ++i) {
        const uint8_t *c0 = &ct[i * 32u];
        const uint8_t *c1 = &ct[i * 32u + OTR128_BLOCK_SIZE];
        uint8_t *m0 = &pt[i * 32u];
        uint8_t *m1 = &pt[i * 32u + OTR128_BLOCK_SIZE];

        xor_block(tmp, ls, c0);
        if (encrypt_block(ctx, tmp, tmp) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        xor_block(m0, tmp, c1);
        xor_block(tmp, l, m0);
        if (encrypt_block(ctx, tmp, tmp) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        xor_block(m1, tmp, c0);
        xor_block_inplace(sum, m1);
        xor_block(l, l, ls);
        gf_double(ls, ls);
    }

    if (last <= OTR128_BLOCK_SIZE) {
        if (encrypt_block(ctx, l, z) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        for (i = 0; i < last; ++i) {
            pt[ell * 32u + i] = (uint8_t)(z[i] ^ ct[ell * 32u + i]);
        }
        copy_pad10(last_block, &pt[ell * 32u], last);
        xor_block_inplace(sum, last_block);
        memcpy(last_mask, l, OTR128_BLOCK_SIZE);
    } else {
        const uint8_t *c0 = &ct[ell * 32u];
        const uint8_t *c1 = &ct[ell * 32u + OTR128_BLOCK_SIZE];
        uint8_t *m0 = &pt[ell * 32u];
        uint8_t *m1 = &pt[ell * 32u + OTR128_BLOCK_SIZE];
        size_t tail = last - OTR128_BLOCK_SIZE;

        copy_pad10(last_block, c1, tail);
        xor_block_inplace(sum, last_block);
        xor_block(tmp, ls, last_block);
        if (encrypt_block(ctx, tmp, tmp) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        xor_block(m0, tmp, c0);
        xor_block(tmp, l, m0);
        if (encrypt_block(ctx, tmp, z) != OTR128_OK) {
            return OTR128_ERR_BACKEND;
        }
        for (i = 0; i < tail; ++i) {
            m1[i] = (uint8_t)(z[i] ^ c1[i]);
        }
        xor_block_inplace(sum, z);
        memcpy(last_mask, ls, OTR128_BLOCK_SIZE);
    }

    gf_double(last_mask, tmp);
    if ((last == OTR128_BLOCK_SIZE) || (last == 2u * OTR128_BLOCK_SIZE)) {
        gf_triple(tmp, tmp);
    } else {
        gf_double(tmp, tmp);
    }
    xor_block(last_mask, last_mask, tmp);
    xor_block(sum, sum, last_mask);
    return encrypt_block(ctx, sum, te);
}

int otr128_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0u;
    size_t i;

    for (i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

uint64_t otr128_get_block_encrypt_count(const otr128_ctx *ctx) {
    return ctx != NULL ? ctx->block_encrypt_count : 0u;
}

void otr128_reset_block_encrypt_count(otr128_ctx *ctx) {
    if (ctx != NULL) {
        ctx->block_encrypt_count = 0u;
    }
}

int otr128_init(otr128_ctx *ctx,
                const otr128_backend *backend,
                const uint8_t key[OTR128_KEY_SIZE]) {
    uint8_t zero[OTR128_BLOCK_SIZE] = {0};

    if (ctx == NULL || backend == NULL || key == NULL || backend->vtable == NULL) {
        return OTR128_ERR_PARAM;
    }
    if (backend->state_size > sizeof(ctx->backend_state)) {
        return OTR128_ERR_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->backend = backend;
    if (backend->vtable->set_encrypt_key(ctx->backend_state, key) != OTR128_OK) {
        otr128_clear(ctx);
        return OTR128_ERR_BACKEND;
    }
    if (encrypt_block(ctx, zero, ctx->q_l) != OTR128_OK) {
        otr128_clear(ctx);
        return OTR128_ERR_BACKEND;
    }
    ctx->initialized = 1;
    return OTR128_OK;
}

void otr128_clear(otr128_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->backend != NULL && ctx->backend->vtable != NULL && ctx->backend->vtable->clear != NULL) {
        ctx->backend->vtable->clear(ctx->backend_state);
    }
    memset(ctx, 0, sizeof(*ctx));
}

int otr128_seal(otr128_ctx *ctx,
                const uint8_t *nonce,
                size_t nonce_len,
                const uint8_t *ad,
                size_t ad_len,
                const uint8_t *pt,
                size_t pt_len,
                uint8_t *ct,
                uint8_t *tag,
                size_t tag_len) {
    uint8_t ta[OTR128_BLOCK_SIZE];
    uint8_t u[OTR128_BLOCK_SIZE];
    uint8_t te[OTR128_BLOCK_SIZE];

    if (ctx == NULL || !ctx->initialized || nonce == NULL || ct == NULL || tag == NULL) {
        return OTR128_ERR_PARAM;
    }
    if (tag_len < OTR128_TAG_MIN || tag_len > OTR128_TAG_MAX ||
        nonce_len < OTR128_NONCE_MIN || nonce_len > OTR128_NONCE_MAX) {
        return OTR128_ERR_PARAM;
    }
    if ((pt_len > 0u && pt == NULL) || (ad_len > 0u && ad == NULL)) {
        return OTR128_ERR_PARAM;
    }

    if (begin_message(ctx) != OTR128_OK) {
        return OTR128_ERR_BACKEND;
    }
    if (compute_serial_ad_tag(ctx, ad, ad_len, ta) != OTR128_OK) {
        end_message(ctx);
        return OTR128_ERR_BACKEND;
    }
    if (process_nonce(ctx, tag_len, nonce, nonce_len, ta, u) != OTR128_OK) {
        end_message(ctx);
        return OTR128_ERR_BACKEND;
    }
    if (ef_serial(ctx, pt, pt_len, u, ct, te) != OTR128_OK) {
        end_message(ctx);
        return OTR128_ERR_BACKEND;
    }
    end_message(ctx);
    memcpy(tag, te, tag_len);
    return OTR128_OK;
}

int otr128_open(otr128_ctx *ctx,
                const uint8_t *nonce,
                size_t nonce_len,
                const uint8_t *ad,
                size_t ad_len,
                const uint8_t *ct,
                size_t ct_len,
                const uint8_t *tag,
                size_t tag_len,
                uint8_t *pt) {
    uint8_t ta[OTR128_BLOCK_SIZE];
    uint8_t u[OTR128_BLOCK_SIZE];
    uint8_t te[OTR128_BLOCK_SIZE];

    if (ctx == NULL || !ctx->initialized || nonce == NULL || ct == NULL || tag == NULL || pt == NULL) {
        return OTR128_ERR_PARAM;
    }
    if (tag_len < OTR128_TAG_MIN || tag_len > OTR128_TAG_MAX ||
        nonce_len < OTR128_NONCE_MIN || nonce_len > OTR128_NONCE_MAX) {
        return OTR128_ERR_PARAM;
    }
    if (ad_len > 0u && ad == NULL) {
        return OTR128_ERR_PARAM;
    }

    if (begin_message(ctx) != OTR128_OK) {
        return OTR128_ERR_BACKEND;
    }
    if (compute_serial_ad_tag(ctx, ad, ad_len, ta) != OTR128_OK) {
        end_message(ctx);
        return OTR128_ERR_BACKEND;
    }
    if (process_nonce(ctx, tag_len, nonce, nonce_len, ta, u) != OTR128_OK) {
        end_message(ctx);
        return OTR128_ERR_BACKEND;
    }
    if (df_serial(ctx, ct, ct_len, u, pt, te) != OTR128_OK) {
        end_message(ctx);
        return OTR128_ERR_BACKEND;
    }
    end_message(ctx);
    if (!otr128_constant_time_eq(te, tag, tag_len)) {
        memset(pt, 0, ct_len);
        return OTR128_ERR_AUTH;
    }
    return OTR128_OK;
}
