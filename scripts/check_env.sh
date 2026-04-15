#!/bin/sh
set -eu

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing: $1" >&2
        return 1
    fi
}

need cmake
need ninja
need cc
need arm-none-eabi-gcc

if ! command -v idf.py >/dev/null 2>&1; then
    echo "warning: idf.py not found" >&2
fi
if [ -z "${IDF_PATH:-}" ]; then
    echo "warning: IDF_PATH is not set" >&2
fi
if ! command -v west >/dev/null 2>&1; then
    echo "warning: west not found" >&2
fi
if [ -z "${ZEPHYR_BASE:-}" ]; then
    echo "warning: ZEPHYR_BASE is not set" >&2
fi
if ! command -v openocd >/dev/null 2>&1; then
    echo "warning: openocd not found" >&2
fi
if [ -z "${STM32CUBE_U5_PATH:-}" ]; then
    echo "warning: STM32CUBE_U5_PATH is not set" >&2
fi

echo "environment looks usable"
