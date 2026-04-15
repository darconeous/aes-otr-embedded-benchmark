#ifndef OTR128_BENCH_H
#define OTR128_BENCH_H

#include "otr128.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t (*otr128_now_fn)(void *user);

typedef struct otr128_bench_case {
    size_t pt_len;
    size_t ad_len;
    size_t tag_len;
} otr128_bench_case;

typedef struct otr128_bench_hooks {
    otr128_now_fn now;
    void *user;
    void (*emit_line)(void *user, const char *line);
} otr128_bench_hooks;

void otr128_run_benchmarks(const otr128_backend *backend,
                           const otr128_bench_hooks *hooks);

#ifdef __cplusplus
}
#endif

#endif
