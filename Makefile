BUILD_DIR ?= build/host
NRF52_BOARD ?= nrf52840dk/nrf52840
ZEPHYR_WORKSPACE ?= $(HOME)/zephyrproject
ZEPHYR_BASE ?= $(ZEPHYR_WORKSPACE)/zephyr
ZEPHYR_SDK_INSTALL_DIR ?= $(HOME)/zephyr-sdk-0.17.4
NRF52_BUILD_DIR ?= $(ZEPHYR_WORKSPACE)/build/otr-benchmark-nrf52
WEST_PYTHON ?= /opt/homebrew/Cellar/west/1.5.0/libexec/bin/python
NRF52_FLASH_RUNNER ?=

.PHONY: host-configure host-test host-bench clean check-tools esp32-build esp32-flash nrf52-setup nrf52-build nrf52-flash stm32-build stm32-flash

host-configure:
	cmake -S . -B $(BUILD_DIR) -G Ninja --fresh

host-test: host-configure
	cmake --build $(BUILD_DIR) --target otr128_tests
	ctest --test-dir $(BUILD_DIR) --output-on-failure

host-bench: host-configure
	cmake --build $(BUILD_DIR) --target otr128_bench
	./$(BUILD_DIR)/otr128_bench

clean:
	rm -rf $(BUILD_DIR) build/stm32 build/esp32 embedded/esp32/build $(NRF52_BUILD_DIR)

check-tools:
	./scripts/check_env.sh

esp32-build:
	cd embedded/esp32 && idf.py set-target esp32s3 build

esp32-flash:
	cd embedded/esp32 && idf.py -p $$PORT flash monitor

nrf52-setup:
	$(WEST_PYTHON) -m pip install -r $(ZEPHYR_BASE)/scripts/requirements.txt

nrf52-build: nrf52-setup
	cd $(ZEPHYR_WORKSPACE) && \
	ZEPHYR_BASE=$(ZEPHYR_BASE) \
	ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
	ZEPHYR_SDK_INSTALL_DIR=$(ZEPHYR_SDK_INSTALL_DIR) \
	west build -p auto -s $(CURDIR)/embedded/nrf52 -b $(NRF52_BOARD) --build-dir $(NRF52_BUILD_DIR)

nrf52-flash:
	cd $(ZEPHYR_WORKSPACE) && \
	ZEPHYR_BASE=$(ZEPHYR_BASE) \
	ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
	ZEPHYR_SDK_INSTALL_DIR=$(ZEPHYR_SDK_INSTALL_DIR) \
	west flash $(if $(NRF52_FLASH_RUNNER),--runner $(NRF52_FLASH_RUNNER),) -d $(NRF52_BUILD_DIR)

stm32-build:
	cmake -S embedded/stm32 -B build/stm32 -G Ninja -DCMAKE_TOOLCHAIN_FILE=embedded/stm32/toolchain-gcc-arm-none-eabi.cmake
	cmake --build build/stm32

stm32-flash:
	openocd -f embedded/stm32/openocd.cfg -c "program build/stm32/otr128_stm32.elf verify reset exit"
