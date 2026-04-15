cmake_minimum_required(VERSION 3.20)
project(otr128_stm32 C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT DEFINED STM32CUBE_U5_PATH AND DEFINED ENV{STM32CUBE_U5_PATH})
    set(STM32CUBE_U5_PATH "$ENV{STM32CUBE_U5_PATH}")
endif()

if(NOT DEFINED STM32CUBE_U5_PATH)
    message(FATAL_ERROR "Set STM32CUBE_U5_PATH to your STM32CubeU5 installation")
endif()

set(STM32U5_DEVICE STM32U575xx)
set(STM32U5_STARTUP ${STM32CUBE_U5_PATH}/Drivers/CMSIS/Device/ST/STM32U5xx/Source/Templates/gcc/startup_stm32u575xx.s)
set(STM32U5_SYSTEM ${STM32CUBE_U5_PATH}/Drivers/CMSIS/Device/ST/STM32U5xx/Source/Templates/system_stm32u5xx.c)
set(STM32U5_HAL_SRC ${STM32CUBE_U5_PATH}/Drivers/STM32U5xx_HAL_Driver/Src)

add_executable(otr128_stm32
    src/main.c
    src/hal_port.c
    ../../src/otr128.c
    ../../src/aes128_soft.c
    ../../src/backend_stm32u5.c
    ../../src/bench.c
    ${STM32U5_SYSTEM}
    ${STM32U5_STARTUP}
    ${STM32U5_HAL_SRC}/stm32u5xx_hal.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_cortex.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_cryp.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_cryp_ex.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_flash.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_flash_ex.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_gpio.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_pwr.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_pwr_ex.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_rcc.c
    ${STM32U5_HAL_SRC}/stm32u5xx_hal_rcc_ex.c
)

target_include_directories(otr128_stm32 PRIVATE
    ../../include
    ${STM32CUBE_U5_PATH}/Drivers/CMSIS/Device/ST/STM32U5xx/Include
    ${STM32CUBE_U5_PATH}/Drivers/CMSIS/Include
    ${STM32CUBE_U5_PATH}/Drivers/STM32U5xx_HAL_Driver/Inc
    ${STM32CUBE_U5_PATH}/Drivers/STM32U5xx_HAL_Driver/Inc/Legacy
)

target_compile_definitions(otr128_stm32 PRIVATE
    USE_HAL_DRIVER
    ${STM32U5_DEVICE}
    STM32U5xx
    OTR128_PLATFORM_STM32U5
)

target_compile_options(otr128_stm32 PRIVATE
    -mcpu=cortex-m33
    -mthumb
    -ffunction-sections
    -fdata-sections
    -Wall
    -Wextra
)

target_link_options(otr128_stm32 PRIVATE
    -mcpu=cortex-m33
    -mthumb
    -specs=nano.specs
    -specs=nosys.specs
    -Wl,--gc-sections
    -Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/otr128_stm32.map
    -T${CMAKE_CURRENT_LIST_DIR}/STM32U575ZITX_FLASH.ld
)
