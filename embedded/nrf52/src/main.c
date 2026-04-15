#include "otr128_bench.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

static timing_t g_timing_start;

static void emit_line(void *user, const char *line) {
    (void)user;
    printk("%s\n", line);
}

static uint64_t nrf_now_ns(void *user) {
    timing_t now;

    (void)user;
    now = timing_counter_get();
    return timing_cycles_to_ns(timing_cycles_get(&g_timing_start, &now));
}

int main(void) {
    otr128_bench_hooks hooks;
    const otr128_backend *hw = otr128_backend_nrf52();

    timing_init();
    timing_start();
    g_timing_start = timing_counter_get();

    hooks.now = nrf_now_ns;
    hooks.user = NULL;
    hooks.emit_line = emit_line;
    for (;;) {
        if (hw != NULL) {
            otr128_run_benchmarks(hw, &hooks);
        }
        otr128_run_benchmarks(otr128_backend_soft(), &hooks);
        k_sleep(K_SECONDS(2));
    }
    return 0;
}
