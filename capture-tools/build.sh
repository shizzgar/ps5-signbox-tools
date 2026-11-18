#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
: "${PS5_PAYLOAD_SDK:?Set PS5_PAYLOAD_SDK to an installed PS5 Payload SDK}"
cd -- "$(dirname -- "$0")"
make -C upstream/payload
mkdir -p build
cp upstream/build/ps5loop.elf build/ps5loop.elf
"$PS5_PAYLOAD_SDK/bin/prospero-clang" -O2 -Wall -Wextra -Werror \
    user-id.c -lSceUserService -o build/user-id.elf
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
files = [Path('build/ps5loop.elf'), Path('build/user-id.elf')]
Path('SHA256SUMS.txt').write_text(''.join(
    f'{sha256(p.read_bytes()).hexdigest()}  {p.as_posix()}\n' for p in files))
PY
