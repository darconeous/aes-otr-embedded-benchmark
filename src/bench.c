#include "otr128_bench.h"

#include <stdio.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

static const otr128_bench_case k_cases[] = {
    {0u, 0u, 16u}, {1u, 0u, 16u}, {15u, 8u, 16u}, {16u, 16u, 16u},
    {31u, 24u, 16u}, {32u, 24u, 16u}, {64u, 48u, 16u}, {128u, 16u, 16u},
    {192u, 48u, 16u}
};

static void default_emit(void *user, const char *line) {
    (void)user;
    puts(line);
}

static void emit_blank_line(const otr128_bench_hooks *hooks) {
    hooks->emit_line(hooks->user, "");
}

static const char *current_platform_name(void) {
#if defined(ESP_PLATFORM)
    return "ESP32-S3";
#elif defined(OTR128_PLATFORM_NRF52)
    return "nRF52";
#elif defined(OTR128_PLATFORM_STM32U5)
    return "STM32U5";
#else
    return "Host";
#endif
}

static const char *backend_display_name(const otr128_backend *backend) {
    if (strcmp(backend->name, "esp32-hw") == 0) {
        return "ESP32-S3 Hardware";
    }
    if (strcmp(backend->name, "soft") == 0 || strcmp(backend->name, "software") == 0) {
        return NULL;
    }
    if (strcmp(backend->name, "nrf52-hw") == 0) {
        return "nRF52 Hardware";
    }
    if (strcmp(backend->name, "stm32u5-hw") == 0) {
        return "STM32U5 Hardware";
    }
    return backend->name;
}

static void format_duration(uint64_t ns, char *out, size_t out_size) {
    double value = (double)ns;
    const char *unit = "ns";

    if (ns >= 1000000000ull) {
        value /= 1000000000.0;
        unit = "s";
    } else if (ns >= 1000000ull) {
        value /= 1000000.0;
        unit = "ms";
    } else if (ns >= 1000ull) {
        value /= 1000.0;
        unit = "us";
    }

    snprintf(out, out_size, "%.3f%s", value, unit);
}

static void format_per_op(uint64_t total_ns, uint64_t iterations, char *out, size_t out_size) {
    if (iterations == 0u) {
        snprintf(out, out_size, "n/a");
        return;
    }
    format_duration(total_ns / iterations, out, out_size);
}

static void fill_pattern(uint8_t *dst, size_t len, uint8_t seed) {
    size_t i;
    for (i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(seed + (uint8_t)(i * 17u) + (uint8_t)(i >> 1));
    }
}

static void bench_pause_if_needed(size_t iteration,
                                  const otr128_bench_hooks *hooks,
                                  uint64_t *start_ns) {
#if defined(ESP_PLATFORM)
    if ((iteration != 0u) && ((iteration % 64u) == 0u)) {
        uint64_t pause_start = hooks->now(hooks->user);
        vTaskDelay(1);
        *start_ns += hooks->now(hooks->user) - pause_start;
    }
#else
    (void)iteration;
    (void)hooks;
    (void)start_ns;
#endif
}

static size_t select_iterations(const otr128_bench_case *bc) {
#if defined(ESP_PLATFORM) || defined(OTR128_PLATFORM_NRF52) || defined(OTR128_PLATFORM_STM32U5)
    size_t iterations = 512u;

    if (bc->pt_len == 0u) {
        iterations = 1024u;
    } else if (bc->pt_len <= 32u) {
        iterations = 768u;
    } else if (bc->pt_len <= 64u) {
        iterations = 512u;
    } else if (bc->pt_len <= 128u) {
        iterations = 320u;
    } else {
        iterations = 192u;
    }
    return iterations;
#else
    size_t iterations = 20000u;

    if (bc->pt_len >= 128u) {
        iterations = 6000u;
    } else if (bc->pt_len >= 64u) {
        iterations = 10000u;
    }
    return iterations;
#endif
}

static uint64_t bench_key_setup(const otr128_backend *backend,
                                const uint8_t key[16],
                                size_t iterations,
                                const otr128_bench_hooks *hooks) {
    otr128_ctx ctx;
    uint64_t start = hooks->now(hooks->user);
    size_t i;

    for (i = 0; i < iterations; ++i) {
        bench_pause_if_needed(i, hooks, &start);
        if (otr128_init(&ctx, backend, key) != OTR128_OK) {
            return 0;
        }
        otr128_clear(&ctx);
    }
    return hooks->now(hooks->user) - start;
}

static uint64_t bench_raw_block_encrypt(const otr128_backend *backend,
                                        const uint8_t key[16],
                                        size_t iterations,
                                        const otr128_bench_hooks *hooks) {
    otr128_ctx ctx;
    uint8_t in[16];
    uint8_t out[16];
    uint64_t start;
    size_t i;

    fill_pattern(in, sizeof(in), 0x5au);
    if (otr128_init(&ctx, backend, key) != OTR128_OK) {
        return 0;
    }
    start = hooks->now(hooks->user);
    for (i = 0; i < iterations; ++i) {
        bench_pause_if_needed(i, hooks, &start);
        if (backend->vtable->encrypt_block(ctx.backend_state, in, out) != OTR128_OK) {
            otr128_clear(&ctx);
            return 0;
        }
        in[0] ^= out[0];
    }
    otr128_clear(&ctx);
    return hooks->now(hooks->user) - start;
}

static uint64_t bench_scoped_block_encrypt(const otr128_backend *backend,
                                           const uint8_t key[16],
                                           size_t iterations,
                                           const otr128_bench_hooks *hooks) {
    otr128_ctx ctx;
    uint8_t in[16];
    uint8_t out[16];
    uint64_t start;
    size_t i;

    fill_pattern(in, sizeof(in), 0x6cu);
    if (otr128_init(&ctx, backend, key) != OTR128_OK) {
        return 0;
    }
    if (ctx.backend->vtable->begin_message != NULL &&
        ctx.backend->vtable->begin_message(ctx.backend_state) != OTR128_OK) {
        otr128_clear(&ctx);
        return 0;
    }
    start = hooks->now(hooks->user);
    for (i = 0; i < iterations; ++i) {
        bench_pause_if_needed(i, hooks, &start);
        if (backend->vtable->encrypt_block(ctx.backend_state, in, out) != OTR128_OK) {
            if (ctx.backend->vtable->end_message != NULL) {
                ctx.backend->vtable->end_message(ctx.backend_state);
            }
            otr128_clear(&ctx);
            return 0;
        }
        in[0] ^= out[0];
    }
    if (ctx.backend->vtable->end_message != NULL) {
        ctx.backend->vtable->end_message(ctx.backend_state);
    }
    otr128_clear(&ctx);
    return hooks->now(hooks->user) - start;
}

static uint64_t bench_seal_open(const otr128_backend *backend,
                                const otr128_bench_case *bc,
                                int rekey_every_iter,
                                const otr128_bench_hooks *hooks,
                                uint64_t *seal_ns,
                                uint64_t *open_ns,
                                uint64_t *total_ns) {
    otr128_ctx ctx;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t ad[48];
    uint8_t pt[192];
    uint8_t ct[192];
    uint8_t tag[16];
    uint8_t out[192];
    size_t iterations;
    size_t i;
    uint64_t start;

    fill_pattern(key, sizeof(key), (uint8_t)(0x10u + rekey_every_iter));
    fill_pattern(nonce, sizeof(nonce), (uint8_t)(0x30u + rekey_every_iter));
    fill_pattern(ad, sizeof(ad), 0x55u);
    fill_pattern(pt, sizeof(pt), 0x80u);
    if (otr128_init(&ctx, backend, key) != OTR128_OK) {
        return 0;
    }

    iterations = select_iterations(bc);

    start = hooks->now(hooks->user);
    for (i = 0; i < iterations; ++i) {
        bench_pause_if_needed(i, hooks, &start);
        if (rekey_every_iter) {
            key[15] = (uint8_t)i;
            if (otr128_init(&ctx, backend, key) != OTR128_OK) {
                return 0;
            }
        }
        if (otr128_seal(&ctx, nonce, sizeof(nonce), ad, bc->ad_len, pt, bc->pt_len, ct, tag, bc->tag_len) != OTR128_OK) {
            return 0;
        }
    }
    *seal_ns = hooks->now(hooks->user) - start;

    start = hooks->now(hooks->user);
    for (i = 0; i < iterations; ++i) {
        bench_pause_if_needed(i, hooks, &start);
        if (rekey_every_iter) {
            key[15] = (uint8_t)i;
            if (otr128_init(&ctx, backend, key) != OTR128_OK) {
                return 0;
            }
            if (otr128_seal(&ctx, nonce, sizeof(nonce), ad, bc->ad_len, pt, bc->pt_len, ct, tag, bc->tag_len) != OTR128_OK) {
                return 0;
            }
        }
        if (otr128_open(&ctx, nonce, sizeof(nonce), ad, bc->ad_len, ct, bc->pt_len, tag, bc->tag_len, out) != OTR128_OK) {
            return 0;
        }
    }
    *open_ns = hooks->now(hooks->user) - start;

    start = hooks->now(hooks->user);
    for (i = 0; i < iterations; ++i) {
        bench_pause_if_needed(i, hooks, &start);
        if (rekey_every_iter) {
            key[15] = (uint8_t)i;
            if (otr128_init(&ctx, backend, key) != OTR128_OK) {
                return 0;
            }
        }
        if (otr128_seal(&ctx, nonce, sizeof(nonce), ad, bc->ad_len, pt, bc->pt_len, ct, tag, bc->tag_len) != OTR128_OK) {
            return 0;
        }
        if (otr128_open(&ctx, nonce, sizeof(nonce), ad, bc->ad_len, ct, bc->pt_len, tag, bc->tag_len, out) != OTR128_OK) {
            return 0;
        }
    }
    *total_ns = hooks->now(hooks->user) - start;
    otr128_clear(&ctx);
    return (uint64_t)iterations;
}

void otr128_run_benchmarks(const otr128_backend *backend,
                           const otr128_bench_hooks *hooks) {
    otr128_bench_hooks local_hooks;
    char line[512];
    uint8_t key[16];
    size_t case_idx;
    int pass;

    if (backend == NULL || hooks == NULL || hooks->now == NULL) {
        return;
    }

    local_hooks = *hooks;
    if (local_hooks.emit_line == NULL) {
        local_hooks.emit_line = default_emit;
    }

    fill_pattern(key, sizeof(key), 0x11u);
    for (pass = 0; pass < 2; ++pass) {
        uint64_t key_setup_ns;
        uint64_t aes1_iso_ns;
        uint64_t aesn_scoped_ns;
        char key_setup_per_op_buf[32];
        char aes1_iso_per_op_buf[32];
        char aesn_scoped_per_op_buf[32];
        uint64_t key_setup_iterations;
        const char *backend_name = backend_display_name(backend);
        char software_name[64];

        if (backend_name == NULL) {
            snprintf(software_name, sizeof(software_name), "%s Software", current_platform_name());
            backend_name = software_name;
        }

        snprintf(line,
                 sizeof(line),
                 "## %s Benchmarks, %s",
                 backend_name,
                 pass == 0 ? "Reuse-Key" : "Rekey-Each-Iter");
        local_hooks.emit_line(local_hooks.user, line);
        emit_blank_line(&local_hooks);
        key_setup_iterations =
#if defined(ESP_PLATFORM) || defined(OTR128_PLATFORM_NRF52) || defined(OTR128_PLATFORM_STM32U5)
            (uint64_t)(pass == 0 ? 512u : 1024u);
#else
            (uint64_t)(pass == 0 ? 5000u : 20000u);
#endif
        key_setup_ns = bench_key_setup(backend, key, (size_t)key_setup_iterations, &local_hooks);
        aes1_iso_ns = bench_raw_block_encrypt(backend, key, (size_t)key_setup_iterations, &local_hooks);
        aesn_scoped_ns = bench_scoped_block_encrypt(backend, key, (size_t)key_setup_iterations, &local_hooks);
        format_per_op(key_setup_ns, key_setup_iterations, key_setup_per_op_buf, sizeof(key_setup_per_op_buf));
        format_per_op(aes1_iso_ns, key_setup_iterations, aes1_iso_per_op_buf, sizeof(aes1_iso_per_op_buf));
        format_per_op(aesn_scoped_ns, key_setup_iterations, aesn_scoped_per_op_buf, sizeof(aesn_scoped_per_op_buf));

        local_hooks.emit_line(local_hooks.user, "| AES metric |    per op |");
        local_hooks.emit_line(local_hooks.user, "|:-----------|----------:|");
        snprintf(line, sizeof(line), "| %-10s | %9s |", "key_setup", key_setup_per_op_buf);
        local_hooks.emit_line(local_hooks.user, line);
        snprintf(line, sizeof(line), "| %-10s | %9s |", "aes1_iso", aes1_iso_per_op_buf);
        local_hooks.emit_line(local_hooks.user, line);
        snprintf(line, sizeof(line), "| %-10s | %9s |", "aesN", aesn_scoped_per_op_buf);
        local_hooks.emit_line(local_hooks.user, line);
        emit_blank_line(&local_hooks);
        local_hooks.emit_line(local_hooks.user, "| pt_len | ad_len | tag_len |  iter |   seal/op | seal aes blocks |   open/op | open aes blocks |");
        local_hooks.emit_line(local_hooks.user, "|------:|-------:|--------:|------:|----------:|----------------:|----------:|----------------:|");

        for (case_idx = 0; case_idx < (sizeof(k_cases) / sizeof(k_cases[0])); ++case_idx) {
            uint64_t seal_ns;
            uint64_t open_ns;
            uint64_t iterations;
            char seal_buf[32];
            char seal_per_op_buf[32];
            char open_buf[32];
            char open_per_op_buf[32];
            uint64_t seal_blocks;
            uint64_t open_blocks;

            iterations = bench_seal_open(backend, &k_cases[case_idx], pass, &local_hooks, &seal_ns, &open_ns, &(uint64_t){0});
            format_per_op(seal_ns, iterations, seal_per_op_buf, sizeof(seal_per_op_buf));
            format_per_op(open_ns, iterations, open_per_op_buf, sizeof(open_per_op_buf));
            {
                otr128_ctx count_ctx;
                uint8_t nonce[12];
                uint8_t ad[48];
                uint8_t pt[192];
                uint8_t ct[192];
                uint8_t tag[16];
                uint8_t out[192];

                fill_pattern(nonce, sizeof(nonce), (uint8_t)(0x30u + pass));
                fill_pattern(ad, sizeof(ad), 0x55u);
                fill_pattern(pt, sizeof(pt), 0x80u);
                otr128_init(&count_ctx, backend, key);
                otr128_reset_block_encrypt_count(&count_ctx);
                otr128_seal(&count_ctx, nonce, sizeof(nonce), ad, k_cases[case_idx].ad_len, pt, k_cases[case_idx].pt_len, ct, tag, k_cases[case_idx].tag_len);
                seal_blocks = otr128_get_block_encrypt_count(&count_ctx);
                otr128_reset_block_encrypt_count(&count_ctx);
                otr128_open(&count_ctx, nonce, sizeof(nonce), ad, k_cases[case_idx].ad_len, ct, k_cases[case_idx].pt_len, tag, k_cases[case_idx].tag_len, out);
                open_blocks = otr128_get_block_encrypt_count(&count_ctx);
                otr128_clear(&count_ctx);
            }
            snprintf(line, sizeof(line),
                     "| %6zu | %6zu | %7zu | %5llu | %9s | %15llu | %9s | %15llu |",
                     k_cases[case_idx].pt_len,
                     k_cases[case_idx].ad_len,
                     k_cases[case_idx].tag_len,
                     (unsigned long long)iterations,
                     seal_per_op_buf,
                     (unsigned long long)seal_blocks,
                     open_per_op_buf,
                     (unsigned long long)open_blocks);
            local_hooks.emit_line(local_hooks.user, line);
        }
        emit_blank_line(&local_hooks);
    }
}
