cmake_minimum_required(VERSION 3.20)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(otr128_nrf52)

target_sources(app PRIVATE
    src/main.c
    ../../src/otr128.c
    ../../src/aes128_soft.c
    ../../src/backend_nrf52.c
    ../../src/bench.c
)
target_include_directories(app PRIVATE ../../include)
target_compile_definitions(app PRIVATE OTR128_PLATFORM_NRF52)
