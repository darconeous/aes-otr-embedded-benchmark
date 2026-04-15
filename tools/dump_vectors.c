#include "otr128.h"

#include <stdio.h>
#include <string.h>

typedef struct vector_case {
    const char *name;
    size_t nonce_len;
    size_t ad_len;
    size_t pt_len;
    size_t tag_len;
} vector_case;

static void fill_pattern(uint8_t *dst, size_t len, uint8_t seed) {
    size_t i;
    for (i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(seed + (uint8_t)(i * 17u) + (uint8_t)(i >> 1));
    }
}

static void print_hex(const uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
}

int main(void) {
    static const vector_case cases[] = {
        {"empty", 12u, 0u, 0u, 16u},
        {"single", 12u, 0u, 1u, 16u},
        {"partial", 12u, 8u, 15u, 16u},
        {"block", 12u, 16u, 16u, 16u},
        {"chunk-partial", 12u, 24u, 31u, 12u},
        {"chunk-full", 12u, 24u, 32u, 12u},
        {"multi", 12u, 48u, 64u, 16u},
        {"long", 12u, 16u, 128u, 8u}
    };
    uint8_t key[16];
    uint8_t nonce[15];
    uint8_t ad[64];
    uint8_t pt[192];
    uint8_t ct[192];
    uint8_t tag[16];
    otr128_ctx ctx;
    size_t i;

    fill_pattern(key, sizeof(key), 0x11u);
    fill_pattern(nonce, sizeof(nonce), 0x22u);
    fill_pattern(ad, sizeof(ad), 0x33u);
    fill_pattern(pt, sizeof(pt), 0x44u);
    otr128_init(&ctx, otr128_backend_soft(), key);

    for (i = 0; i < (sizeof(cases) / sizeof(cases[0])); ++i) {
        memset(ct, 0, sizeof(ct));
        memset(tag, 0, sizeof(tag));
        otr128_seal(&ctx, nonce, cases[i].nonce_len, ad, cases[i].ad_len, pt, cases[i].pt_len, ct, tag, cases[i].tag_len);
        printf("%s\n", cases[i].name);
        printf("nonce=");
        print_hex(nonce, cases[i].nonce_len);
        printf("\nad=");
        print_hex(ad, cases[i].ad_len);
        printf("\npt=");
        print_hex(pt, cases[i].pt_len);
        printf("\nct=");
        print_hex(ct, cases[i].pt_len);
        printf("\ntag=");
        print_hex(tag, cases[i].tag_len);
        printf("\n\n");
    }

    otr128_clear(&ctx);
    return 0;
}
