#include "otr128.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct aes128_soft_state {
    uint32_t round_keys[44];
} aes128_soft_state;

_Static_assert(sizeof(aes128_soft_state) <= OTR128_BACKEND_STATE_BYTES,
               "software backend state exceeds OTR128_BACKEND_STATE_BYTES");

static const uint8_t k_sbox[256] = {
    0x63u, 0x7cu, 0x77u, 0x7bu, 0xf2u, 0x6bu, 0x6fu, 0xc5u, 0x30u, 0x01u, 0x67u, 0x2bu,
    0xfeu, 0xd7u, 0xabu, 0x76u, 0xcau, 0x82u, 0xc9u, 0x7du, 0xfau, 0x59u, 0x47u, 0xf0u,
    0xadu, 0xd4u, 0xa2u, 0xafu, 0x9cu, 0xa4u, 0x72u, 0xc0u, 0xb7u, 0xfdu, 0x93u, 0x26u,
    0x36u, 0x3fu, 0xf7u, 0xccu, 0x34u, 0xa5u, 0xe5u, 0xf1u, 0x71u, 0xd8u, 0x31u, 0x15u,
    0x04u, 0xc7u, 0x23u, 0xc3u, 0x18u, 0x96u, 0x05u, 0x9au, 0x07u, 0x12u, 0x80u, 0xe2u,
    0xebu, 0x27u, 0xb2u, 0x75u, 0x09u, 0x83u, 0x2cu, 0x1au, 0x1bu, 0x6eu, 0x5au, 0xa0u,
    0x52u, 0x3bu, 0xd6u, 0xb3u, 0x29u, 0xe3u, 0x2fu, 0x84u, 0x53u, 0xd1u, 0x00u, 0xedu,
    0x20u, 0xfcu, 0xb1u, 0x5bu, 0x6au, 0xcbu, 0xbeu, 0x39u, 0x4au, 0x4cu, 0x58u, 0xcfu,
    0xd0u, 0xefu, 0xaau, 0xfbu, 0x43u, 0x4du, 0x33u, 0x85u, 0x45u, 0xf9u, 0x02u, 0x7fu,
    0x50u, 0x3cu, 0x9fu, 0xa8u, 0x51u, 0xa3u, 0x40u, 0x8fu, 0x92u, 0x9du, 0x38u, 0xf5u,
    0xbcu, 0xb6u, 0xdau, 0x21u, 0x10u, 0xffu, 0xf3u, 0xd2u, 0xcdu, 0x0cu, 0x13u, 0xecu,
    0x5fu, 0x97u, 0x44u, 0x17u, 0xc4u, 0xa7u, 0x7eu, 0x3du, 0x64u, 0x5du, 0x19u, 0x73u,
    0x60u, 0x81u, 0x4fu, 0xdcu, 0x22u, 0x2au, 0x90u, 0x88u, 0x46u, 0xeeu, 0xb8u, 0x14u,
    0xdeu, 0x5eu, 0x0bu, 0xdbu, 0xe0u, 0x32u, 0x3au, 0x0au, 0x49u, 0x06u, 0x24u, 0x5cu,
    0xc2u, 0xd3u, 0xacu, 0x62u, 0x91u, 0x95u, 0xe4u, 0x79u, 0xe7u, 0xc8u, 0x37u, 0x6du,
    0x8du, 0xd5u, 0x4eu, 0xa9u, 0x6cu, 0x56u, 0xf4u, 0xeau, 0x65u, 0x7au, 0xaeu, 0x08u,
    0xbau, 0x78u, 0x25u, 0x2eu, 0x1cu, 0xa6u, 0xb4u, 0xc6u, 0xe8u, 0xddu, 0x74u, 0x1fu,
    0x4bu, 0xbdu, 0x8bu, 0x8au, 0x70u, 0x3eu, 0xb5u, 0x66u, 0x48u, 0x03u, 0xf6u, 0x0eu,
    0x61u, 0x35u, 0x57u, 0xb9u, 0x86u, 0xc1u, 0x1du, 0x9eu, 0xe1u, 0xf8u, 0x98u, 0x11u,
    0x69u, 0xd9u, 0x8eu, 0x94u, 0x9bu, 0x1eu, 0x87u, 0xe9u, 0xceu, 0x55u, 0x28u, 0xdfu,
    0x8cu, 0xa1u, 0x89u, 0x0du, 0xbfu, 0xe6u, 0x42u, 0x68u, 0x41u, 0x99u, 0x2du, 0x0fu,
    0xb0u, 0x54u, 0xbbu, 0x16u
};

static const uint32_t k_rcon[10] = {
    0x01000000u, 0x02000000u, 0x04000000u, 0x08000000u, 0x10000000u,
    0x20000000u, 0x40000000u, 0x80000000u, 0x1b000000u, 0x36000000u
};

static uint32_t g_te0[256];
static uint32_t g_te1[256];
static uint32_t g_te2[256];
static uint32_t g_te3[256];
static int g_tables_ready = 0;

static uint32_t load_be32(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) |
           (uint32_t)src[3];
}

static void store_be32(uint8_t dst[4], uint32_t value) {
    dst[0] = (uint8_t)(value >> 24);
    dst[1] = (uint8_t)(value >> 16);
    dst[2] = (uint8_t)(value >> 8);
    dst[3] = (uint8_t)value;
}

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80u) != 0u ? 0x1bu : 0x00u));
}

static void aes128_soft_init_tables(void) {
    size_t i;

    if (g_tables_ready) {
        return;
    }

    for (i = 0; i < 256u; ++i) {
        uint8_t s = k_sbox[i];
        uint8_t s2 = xtime(s);
        uint8_t s3 = (uint8_t)(s2 ^ s);

        g_te0[i] = ((uint32_t)s2 << 24) |
                   ((uint32_t)s << 16) |
                   ((uint32_t)s << 8) |
                   (uint32_t)s3;
        g_te1[i] = ((uint32_t)s3 << 24) |
                   ((uint32_t)s2 << 16) |
                   ((uint32_t)s << 8) |
                   (uint32_t)s;
        g_te2[i] = ((uint32_t)s << 24) |
                   ((uint32_t)s3 << 16) |
                   ((uint32_t)s2 << 8) |
                   (uint32_t)s;
        g_te3[i] = ((uint32_t)s << 24) |
                   ((uint32_t)s << 16) |
                   ((uint32_t)s3 << 8) |
                   (uint32_t)s2;
    }

    g_tables_ready = 1;
}

static uint32_t sub_word(uint32_t word) {
    return ((uint32_t)k_sbox[(word >> 24) & 0xffu] << 24) |
           ((uint32_t)k_sbox[(word >> 16) & 0xffu] << 16) |
           ((uint32_t)k_sbox[(word >> 8) & 0xffu] << 8) |
           (uint32_t)k_sbox[word & 0xffu];
}

static uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

static int aes128_soft_set_encrypt_key(void *state, const uint8_t key[OTR128_KEY_SIZE]) {
    aes128_soft_state *ctx = (aes128_soft_state *)state;
    size_t i;

    if (ctx == NULL || key == NULL) {
        return -1;
    }

    aes128_soft_init_tables();

    for (i = 0; i < 4u; ++i) {
        ctx->round_keys[i] = load_be32(&key[i * 4u]);
    }

    for (i = 4u; i < 44u; ++i) {
        uint32_t temp = ctx->round_keys[i - 1u];
        if ((i & 3u) == 0u) {
            temp = sub_word(rot_word(temp)) ^ k_rcon[(i / 4u) - 1u];
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4u] ^ temp;
    }

    return OTR128_OK;
}

static int aes128_soft_encrypt_block(const void *state,
                                     const uint8_t in[OTR128_BLOCK_SIZE],
                                     uint8_t out[OTR128_BLOCK_SIZE]) {
    const aes128_soft_state *ctx = (const aes128_soft_state *)state;
    const uint32_t *rk;
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    size_t round;

    if (ctx == NULL || in == NULL || out == NULL) {
        return -1;
    }

    rk = ctx->round_keys;
    s0 = load_be32(&in[0]) ^ rk[0];
    s1 = load_be32(&in[4]) ^ rk[1];
    s2 = load_be32(&in[8]) ^ rk[2];
    s3 = load_be32(&in[12]) ^ rk[3];

    rk += 4;
    for (round = 1u; round < 10u; ++round, rk += 4) {
        t0 = g_te0[(s0 >> 24) & 0xffu] ^
             g_te1[(s1 >> 16) & 0xffu] ^
             g_te2[(s2 >> 8) & 0xffu] ^
             g_te3[s3 & 0xffu] ^
             rk[0];
        t1 = g_te0[(s1 >> 24) & 0xffu] ^
             g_te1[(s2 >> 16) & 0xffu] ^
             g_te2[(s3 >> 8) & 0xffu] ^
             g_te3[s0 & 0xffu] ^
             rk[1];
        t2 = g_te0[(s2 >> 24) & 0xffu] ^
             g_te1[(s3 >> 16) & 0xffu] ^
             g_te2[(s0 >> 8) & 0xffu] ^
             g_te3[s1 & 0xffu] ^
             rk[2];
        t3 = g_te0[(s3 >> 24) & 0xffu] ^
             g_te1[(s0 >> 16) & 0xffu] ^
             g_te2[(s1 >> 8) & 0xffu] ^
             g_te3[s2 & 0xffu] ^
             rk[3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    t0 = ((uint32_t)k_sbox[(s0 >> 24) & 0xffu] << 24) |
         ((uint32_t)k_sbox[(s1 >> 16) & 0xffu] << 16) |
         ((uint32_t)k_sbox[(s2 >> 8) & 0xffu] << 8) |
         (uint32_t)k_sbox[s3 & 0xffu];
    t1 = ((uint32_t)k_sbox[(s1 >> 24) & 0xffu] << 24) |
         ((uint32_t)k_sbox[(s2 >> 16) & 0xffu] << 16) |
         ((uint32_t)k_sbox[(s3 >> 8) & 0xffu] << 8) |
         (uint32_t)k_sbox[s0 & 0xffu];
    t2 = ((uint32_t)k_sbox[(s2 >> 24) & 0xffu] << 24) |
         ((uint32_t)k_sbox[(s3 >> 16) & 0xffu] << 16) |
         ((uint32_t)k_sbox[(s0 >> 8) & 0xffu] << 8) |
         (uint32_t)k_sbox[s1 & 0xffu];
    t3 = ((uint32_t)k_sbox[(s3 >> 24) & 0xffu] << 24) |
         ((uint32_t)k_sbox[(s0 >> 16) & 0xffu] << 16) |
         ((uint32_t)k_sbox[(s1 >> 8) & 0xffu] << 8) |
         (uint32_t)k_sbox[s2 & 0xffu];

    store_be32(&out[0], t0 ^ rk[0]);
    store_be32(&out[4], t1 ^ rk[1]);
    store_be32(&out[8], t2 ^ rk[2]);
    store_be32(&out[12], t3 ^ rk[3]);
    return OTR128_OK;
}

static void aes128_soft_clear(void *state) {
    if (state != NULL) {
        memset(state, 0, sizeof(aes128_soft_state));
    }
}

static const otr128_backend_vtable k_soft_vtable = {
    .set_encrypt_key = aes128_soft_set_encrypt_key,
    .begin_message = NULL,
    .encrypt_block = aes128_soft_encrypt_block,
    .end_message = NULL,
    .clear = aes128_soft_clear,
};

static const otr128_backend k_soft_backend = {
    .name = "software",
    .state_size = sizeof(aes128_soft_state),
    .vtable = &k_soft_vtable,
};

const otr128_backend *otr128_backend_soft(void) {
    return &k_soft_backend;
}
