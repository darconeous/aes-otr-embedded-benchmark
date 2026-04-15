#include "otr128.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    static const char *digits = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; ++i) {
        const char *hi = strchr(digits, (int)hex[i * 2] | 32);
        const char *lo = strchr(digits, (int)hex[i * 2 + 1] | 32);
        if (hi == NULL || lo == NULL) {
            fprintf(stderr, "invalid hex\n");
            exit(1);
        }
        out[i] = (uint8_t)(((hi - digits) << 4) | (lo - digits));
    }
}

static void fill_pattern(uint8_t *dst, size_t len, uint8_t seed) {
    size_t i;
    for (i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(seed + (uint8_t)(i * 17u) + (uint8_t)(i >> 1));
    }
}

static int expect_bytes(const char *label, const uint8_t *actual, const uint8_t *expected, size_t len) {
    if (memcmp(actual, expected, len) != 0) {
        size_t i;
        fprintf(stderr, "%s mismatch\nactual  :", label);
        for (i = 0; i < len; ++i) {
            fprintf(stderr, "%02x", actual[i]);
        }
        fprintf(stderr, "\nexpected:");
        for (i = 0; i < len; ++i) {
            fprintf(stderr, "%02x", expected[i]);
        }
        fprintf(stderr, "\n");
        return 0;
    }
    return 1;
}

static int test_aes_block(void) {
    otr128_ctx ctx;
    uint8_t key[16];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t expected[16];

    hex_to_bytes("000102030405060708090a0b0c0d0e0f", key, sizeof(key));
    hex_to_bytes("00112233445566778899aabbccddeeff", pt, sizeof(pt));
    hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a", expected, sizeof(expected));
    if (otr128_init(&ctx, otr128_backend_soft(), key) != OTR128_OK) {
        return 0;
    }
    if (ctx.backend->vtable->encrypt_block(ctx.backend_state, pt, ct) != OTR128_OK) {
        return 0;
    }
    return expect_bytes("aes-128-ecb", ct, expected, sizeof(expected));
}

typedef struct otr_case {
    const char *name;
    const char *nonce_hex;
    const char *ad_hex;
    const char *pt_hex;
    const char *ct_hex;
    const char *tag_hex;
} otr_case;

static int test_known_vectors(void) {
    static const otr_case cases[] = {
        {
            "empty",
            "2233455668798b9caebfd1e2",
            "",
            "",
            "",
            "f5b47c2dd986f1ffd8c055b461f02984"
        },
        {
            "single",
            "2233455668798b9caebfd1e2",
            "",
            "44",
            "40",
            "3d99df82f5121b920bb70eebead446fb"
        },
        {
            "partial",
            "2233455668798b9caebfd1e2",
            "33445667798a9cad",
            "445567788a9badbed0e1f304162739",
            "28f8146baa69611171a5a32ee75d7b",
            "388cdb953f1277f23f30e9e73b57c4ed"
        },
        {
            "block",
            "2233455668798b9caebfd1e2",
            "33445667798a9cadbfd0e2f305162839",
            "445567788a9badbed0e1f3041627394a",
            "ed3f137094e54fc1f52e0c683bd1b99b",
            "ce778906b226f3bf66dec12606dfb9cc"
        },
        {
            "chunk-partial",
            "2233455668798b9caebfd1e2",
            "33445667798a9cadbfd0e2f3051628394b5c6e7f91a2b4c5",
            "445567788a9badbed0e1f3041627394a5c6d7f90a2b3c5d6e8f90b1c2e3f51",
            "9d49499e02b0a832e2725089f1c2f025a8a1273d813eeee74bda3ba70cb768",
            "adf68cc83102b013e72d3832"
        },
        {
            "chunk-full",
            "2233455668798b9caebfd1e2",
            "33445667798a9cadbfd0e2f3051628394b5c6e7f91a2b4c5",
            "445567788a9badbed0e1f3041627394a5c6d7f90a2b3c5d6e8f90b1c2e3f5162",
            "6704cae9b81389c5181d8cdc41b8a6f0a8a1273d813eeee74bda3ba70cb76800",
            "0bcf437dc42a7c1d811945de"
        },
        {
            "multi",
            "2233455668798b9caebfd1e2",
            "33445667798a9cadbfd0e2f3051628394b5c6e7f91a2b4c5d7e8fa0b1d2e405163748697a9baccddef00122335465869",
            "445567788a9badbed0e1f3041627394a5c6d7f90a2b3c5d6e8f90b1c2e3f5162748597a8bacbddee001123344657697a8c9dafc0d2e3f50618293b4c5e6f8192",
            "c6900692c9ca5171a716604137b94085dddd739214e7fcd30e2992b41f5d8c7067ad08d75fa71be61bf06eae3b9bb5d2d88d49073f2bf4e6cc74ed9d95f7146d",
            "3237471fad3e9e524a596b5301b9e274"
        },
        {
            "long",
            "2233455668798b9caebfd1e2",
            "33445667798a9cadbfd0e2f305162839",
            "445567788a9badbed0e1f3041627394a5c6d7f90a2b3c5d6e8f90b1c2e3f5162748597a8bacbddee001123344657697a8c9dafc0d2e3f50618293b4c5e6f8192a4b5c7d8eafb0d1e30415364768799aabccddff00213253648596b7c8e9fb1c2d4e5f7081a2b3d4e60718394a6b7c9daecfd0f203243556678899bacbecfe1f2",
            "0a0b1f77dad1aeea2bb9e9e941b2967e6a65eeb192a795cdbfe713f7c1f6e30c6561fdbe77426af891e27250071c45029fc3ff2aa32305490fb01b88b19dee338f4e88740f59377096f5ae04d64b15ab86e6fa567a96c3646443cc5f3e44cb7dcae13a03e031f02c97922aeca6c3d642e5c799959f5a4ee420f23e91a11ff67c",
            "98f54d96bddc3ca5"
        }
    };
    otr128_ctx ctx;
    uint8_t key[16];
    size_t idx;

    fill_pattern(key, sizeof(key), 0x11u);
    for (idx = 0; idx < (sizeof(cases) / sizeof(cases[0])); ++idx) {
        const otr_case *tc = &cases[idx];
        size_t nonce_len = strlen(tc->nonce_hex) / 2u;
        size_t ad_len = strlen(tc->ad_hex) / 2u;
        size_t pt_len = strlen(tc->pt_hex) / 2u;
        size_t tag_len = strlen(tc->tag_hex) / 2u;
        uint8_t nonce[15];
        uint8_t ad[64];
        uint8_t pt[192];
        uint8_t ct[192];
        uint8_t tag[16];
        uint8_t out[192];
        uint8_t expected_ct[192];
        uint8_t expected_tag[16];

        memset(nonce, 0, sizeof(nonce));
        memset(ad, 0, sizeof(ad));
        memset(pt, 0, sizeof(pt));
        memset(ct, 0, sizeof(ct));
        memset(tag, 0, sizeof(tag));
        memset(out, 0, sizeof(out));
        hex_to_bytes(tc->nonce_hex, nonce, nonce_len);
        hex_to_bytes(tc->ad_hex, ad, ad_len);
        hex_to_bytes(tc->pt_hex, pt, pt_len);
        hex_to_bytes(tc->ct_hex, expected_ct, pt_len);
        hex_to_bytes(tc->tag_hex, expected_tag, tag_len);

        if (otr128_init(&ctx, otr128_backend_soft(), key) != OTR128_OK) {
            return 0;
        }
        if (otr128_seal(&ctx, nonce, nonce_len, ad, ad_len, pt, pt_len, ct, tag, tag_len) != OTR128_OK) {
            fprintf(stderr, "%s seal failed\n", tc->name);
            return 0;
        }
        if (!expect_bytes(tc->name, ct, expected_ct, pt_len)) {
            return 0;
        }
        if (!expect_bytes(tc->name, tag, expected_tag, tag_len)) {
            return 0;
        }
        if (otr128_open(&ctx, nonce, nonce_len, ad, ad_len, ct, pt_len, tag, tag_len, out) != OTR128_OK) {
            fprintf(stderr, "%s open failed\n", tc->name);
            return 0;
        }
        if (!expect_bytes(tc->name, out, pt, pt_len)) {
            return 0;
        }
    }
    return 1;
}

static int test_round_trip(void) {
    otr128_ctx ctx;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t ad[48];
    uint8_t pt[192];
    uint8_t ct[192];
    uint8_t tag[16];
    uint8_t out[192];
    size_t i;

    for (i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(0x10u + i);
    }
    for (i = 0; i < sizeof(nonce); ++i) {
        nonce[i] = (uint8_t)(0x20u + i);
    }
    for (i = 0; i < sizeof(ad); ++i) {
        ad[i] = (uint8_t)(0x40u + i);
    }
    for (i = 0; i < sizeof(pt); ++i) {
        pt[i] = (uint8_t)(0x80u + i);
    }

    if (otr128_init(&ctx, otr128_backend_soft(), key) != OTR128_OK) {
        return 0;
    }
    if (otr128_seal(&ctx, nonce, sizeof(nonce), ad, 48u, pt, 192u, ct, tag, 16u) != OTR128_OK) {
        return 0;
    }
    if (otr128_open(&ctx, nonce, sizeof(nonce), ad, 48u, ct, 192u, tag, 16u, out) != OTR128_OK) {
        return 0;
    }
    return expect_bytes("round-trip", out, pt, sizeof(pt));
}

static int test_auth_failure(void) {
    otr128_ctx ctx;
    uint8_t key[16] = {0};
    uint8_t nonce[12] = {0};
    uint8_t ad[16] = {1};
    uint8_t pt[31];
    uint8_t ct[31];
    uint8_t tag[12];
    uint8_t out[31];
    size_t i;

    for (i = 0; i < sizeof(pt); ++i) {
        pt[i] = (uint8_t)(0xa0u + i);
    }
    memset(out, 0xaa, sizeof(out));
    if (otr128_init(&ctx, otr128_backend_soft(), key) != OTR128_OK) {
        return 0;
    }
    if (otr128_seal(&ctx, nonce, sizeof(nonce), ad, sizeof(ad), pt, sizeof(pt), ct, tag, sizeof(tag)) != OTR128_OK) {
        return 0;
    }
    tag[0] ^= 0x01u;
    if (otr128_open(&ctx, nonce, sizeof(nonce), ad, sizeof(ad), ct, sizeof(ct), tag, sizeof(tag), out) != OTR128_ERR_AUTH) {
        fprintf(stderr, "authentication failure was not detected\n");
        return 0;
    }
    for (i = 0; i < sizeof(out); ++i) {
        if (out[i] != 0u) {
            fprintf(stderr, "plaintext buffer was not wiped on auth failure\n");
            return 0;
        }
    }
    return 1;
}

static int test_tamper_matrix(void) {
    otr128_ctx ctx;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t ad[24];
    uint8_t pt[32];
    uint8_t ct[32];
    uint8_t tag[16];
    uint8_t out[32];
    uint8_t mutated_nonce[12];
    uint8_t mutated_ad[24];
    uint8_t mutated_ct[32];
    size_t i;

    fill_pattern(key, sizeof(key), 0x41u);
    fill_pattern(nonce, sizeof(nonce), 0x51u);
    fill_pattern(ad, sizeof(ad), 0x61u);
    fill_pattern(pt, sizeof(pt), 0x71u);

    if (otr128_init(&ctx, otr128_backend_soft(), key) != OTR128_OK) {
        return 0;
    }
    if (otr128_seal(&ctx, nonce, sizeof(nonce), ad, sizeof(ad), pt, sizeof(pt), ct, tag, sizeof(tag)) != OTR128_OK) {
        return 0;
    }

    memcpy(mutated_nonce, nonce, sizeof(nonce));
    mutated_nonce[0] ^= 0x80u;
    if (otr128_open(&ctx, mutated_nonce, sizeof(mutated_nonce), ad, sizeof(ad), ct, sizeof(ct), tag, sizeof(tag), out) != OTR128_ERR_AUTH) {
        fprintf(stderr, "tampered nonce accepted\n");
        return 0;
    }

    memcpy(mutated_ad, ad, sizeof(ad));
    mutated_ad[sizeof(ad) - 1u] ^= 0x01u;
    if (otr128_open(&ctx, nonce, sizeof(nonce), mutated_ad, sizeof(mutated_ad), ct, sizeof(ct), tag, sizeof(tag), out) != OTR128_ERR_AUTH) {
        fprintf(stderr, "tampered ad accepted\n");
        return 0;
    }

    memcpy(mutated_ct, ct, sizeof(ct));
    mutated_ct[7] ^= 0x04u;
    if (otr128_open(&ctx, nonce, sizeof(nonce), ad, sizeof(ad), mutated_ct, sizeof(mutated_ct), tag, sizeof(tag), out) != OTR128_ERR_AUTH) {
        fprintf(stderr, "tampered ciphertext accepted\n");
        return 0;
    }

    for (i = 0; i < sizeof(out); ++i) {
        if (out[i] != 0u) {
            fprintf(stderr, "plaintext buffer was not wiped after tamper test\n");
            return 0;
        }
    }
    return 1;
}

int main(void) {
    if (!test_aes_block()) {
        return 1;
    }
    if (!test_known_vectors()) {
        return 1;
    }
    if (!test_round_trip()) {
        return 1;
    }
    if (!test_auth_failure()) {
        return 1;
    }
    if (!test_tamper_matrix()) {
        return 1;
    }
    puts("all tests passed");
    return 0;
}
