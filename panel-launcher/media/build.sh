#!/bin/sh
set -eu

: "${PS5_PAYLOAD_SDK:?Set PS5_PAYLOAD_SDK to the installed SDK directory}"
cd -- "$(dirname -- "$0")"
"$PS5_PAYLOAD_SDK/bin/prospero-clang" -O2 -Wall -Wextra -Werror \
    install.c assets.S -lSceSysmodule -lSceIpmi -o "${1:-ps5-network-media.elf}"
