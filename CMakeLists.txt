cmake_minimum_required(VERSION 3.20)
project(otr_benchmark C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(otr128
    src/aes128_soft.c
    src/backend_esp32.c
    src/backend_nrf52.c
    src/backend_stm32u5.c
    src/bench.c
    src/otr128.c
)
target_include_directories(otr128 PUBLIC include)

add_executable(otr128_tests tests/test_main.c)
target_link_libraries(otr128_tests PRIVATE otr128)

add_executable(otr128_bench platforms/host/main.c)
target_link_libraries(otr128_bench PRIVATE otr128)

add_executable(otr128_dump_vectors tools/dump_vectors.c)
target_link_libraries(otr128_dump_vectors PRIVATE otr128)

include(CTest)
enable_testing()
add_test(NAME otr128_tests COMMAND otr128_tests)
