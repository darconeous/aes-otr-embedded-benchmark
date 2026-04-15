#include "otr128_bench.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

static uint64_t host_now_ns(void *user) {
    struct timespec ts;
    (void)user;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

int main(void) {
    otr128_bench_hooks hooks;

    hooks.now = host_now_ns;
    hooks.user = NULL;
    hooks.emit_line = NULL;
    otr128_run_benchmarks(otr128_backend_soft(), &hooks);
    return 0;
}
