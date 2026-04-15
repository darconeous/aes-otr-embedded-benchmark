#include "otr128_bench.h"

#include <stdio.h>
#include "stm32u5xx_hal.h"

static void emit_line(void *user, const char *line) {
    (void)user;
    puts(line);
}

static uint64_t stm_now_ns(void *user) {
    (void)user;
    return (uint64_t)HAL_GetTick() * 1000000ull;
}

int main(void) {
    otr128_bench_hooks hooks;
    const otr128_backend *hw = otr128_backend_stm32u5();

    HAL_Init();
    hooks.now = stm_now_ns;
    hooks.user = NULL;
    hooks.emit_line = emit_line;
    if (hw != NULL) {
        otr128_run_benchmarks(hw, &hooks);
    }
    otr128_run_benchmarks(otr128_backend_soft(), &hooks);
    for (;;) {
    }
}
