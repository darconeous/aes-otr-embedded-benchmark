#include "otr128_bench.h"

#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define OTR128_ESP_BENCH_STACK_WORDS 12288u

static uint64_t esp_now_ns(void *user);

static void benchmark_task(void *arg) {
    otr128_bench_hooks hooks;
    const otr128_backend *hw = otr128_backend_esp32();
    (void)arg;

    hooks.now = esp_now_ns;
    hooks.user = NULL;
    hooks.emit_line = NULL;
    if (hw != NULL) {
        otr128_run_benchmarks(hw, &hooks);
    }
    otr128_run_benchmarks(otr128_backend_soft(), &hooks);
    vTaskDelete(NULL);
}

static uint64_t esp_now_ns(void *user) {
    (void)user;
    return (uint64_t)esp_timer_get_time() * 1000ull;
}

void app_main(void) {
    xTaskCreatePinnedToCore(benchmark_task,
                            "otr128_bench",
                            OTR128_ESP_BENCH_STACK_WORDS,
                            NULL,
                            tskIDLE_PRIORITY + 1,
                            NULL,
                            tskNO_AFFINITY);
}
