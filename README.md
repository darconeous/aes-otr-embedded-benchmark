# AES-OTRv3 Benchmark

Portable `AES-128 OTRv3` in C with:
- software AES-ECB for host verification
- ESP32-S3 hardware AES backend for ESP-IDF
- nRF52840 hardware AES backend for Zephyr/NCS
- STM32U5 hardware AES backend for STM32Cube/HAL

## Host

Build and test:

```sh
make host-test
```

Run the benchmark:

```sh
make host-bench
```

The host test binary checks:
- AES-128 ECB against the standard NIST known-answer vector
- pinned OTR known-answer vectors for empty, partial, exact-block, multi-block, and truncated-tag cases
- decrypt round-trip
- constant-time authentication failure path behavior, including plaintext wiping

## ESP32-S3

Expected environment:
- ESP-IDF installed
- `IDF_PATH` exported
- `idf.py` on `PATH`

Commands:

```sh
make esp32-build
PORT=/dev/tty.usbmodemXXXX make esp32-flash
```

The ESP32 app runs the hardware AES backend and the software backend back-to-back.

## nRF52840 / SenseCAP T1000-E

Expected environment:
- Zephyr SDK installed
- Zephyr workspace installed separately from this repo
- `west` on `PATH`

Recommended layout:

```sh
~/zephyr-sdk-0.17.4
~/zephyrproject/zephyr
```

One-time setup example:

```sh
cd ~
west init -m https://github.com/zephyrproject-rtos/zephyr --mr v4.3.0 zephyrproject
cd zephyrproject
west update
west zephyr-export
/opt/homebrew/bin/pip install -r ~/zephyrproject/zephyr/scripts/requirements.txt
```

If the SDK is installed in the default location, the Makefile targets below will use it automatically. Override `ZEPHYR_WORKSPACE` or `ZEPHYR_SDK_INSTALL_DIR` if your local setup lives elsewhere.
The default nRF52 build directory is `~/zephyrproject/build/otr-benchmark-nrf52`.

Commands:

```sh
make nrf52-build
make nrf52-flash
```

The default board target is `nrf52840dk/nrf52840`. Override it with `NRF52_BOARD=...` if you have a SenseCAP T1000-E-specific board definition or board overlay in your Zephyr workspace.
If Zephyr's default flash runner for your board is not installed, override it explicitly, for example `make NRF52_FLASH_RUNNER=openocd nrf52-flash`.

## STM32U5

Expected environment:
- STM32CubeU5 installed
- `STM32CUBE_U5_PATH` exported
- `arm-none-eabi-gcc` and `openocd` on `PATH`

Commands:

```sh
make stm32-build
make stm32-flash
```

The STM32U5 build now assumes a concrete STM32U575 target layout:
- GCC Arm Embedded toolchain via `embedded/stm32/toolchain-gcc-arm-none-eabi.cmake`
- CubeU5 startup and CMSIS system files from `${STM32CUBE_U5_PATH}`
- HAL driver sources for AES/CRYP and core clock/power support
- a bundled linker script for an STM32U575ZITx-class flash/RAM layout

If your STM32U5 board uses a different part number or memory map, adjust:
- `STM32U5_DEVICE` in `embedded/stm32/CMakeLists.txt`
- `embedded/stm32/STM32U575ZITX_FLASH.ld`
