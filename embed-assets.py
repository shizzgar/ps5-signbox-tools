#!/usr/bin/env python3
"""Create the asset table included by panel.c."""
from pathlib import Path
import sys

ASSETS = (
    ("/", "index.html", "text/html; charset=utf-8"),
    ("/panel.css", "panel.css", "text/css; charset=utf-8"),
    ("/panel.js", "panel.js", "text/javascript; charset=utf-8"),
    ("/mark.svg", "mark.svg", "image/svg+xml"),
    ("/Inter-Regular.woff", "Inter-Regular.woff", "font/woff"),
    ("/Inter-SemiBold.woff", "Inter-SemiBold.woff", "font/woff"),
)

source = Path(__file__).resolve().parent / "ui"
with Path(sys.argv[1]).open("w", encoding="ascii", newline="\n") as output:
    print("#pragma once", file=output)
    for i, (_, filename, _) in enumerate(ASSETS):
        data = (source / filename).read_bytes()
        print(f"static const unsigned char asset_{i}[] = {{", file=output)
        for offset in range(0, len(data), 16):
            print("    " + ", ".join(f"0x{byte:02x}" for byte in data[offset:offset + 16]) + ",", file=output)
        print("};", file=output)
    print("static const struct asset {", file=output)
    print("    const char *path, *type;", file=output)
    print("    const void *data;", file=output)
    print("    size_t length;", file=output)
    print("} assets[] = {", file=output)
    for i, (route, _, mime) in enumerate(ASSETS):
        print(f'    {{"{route}", "{mime}", asset_{i}, sizeof(asset_{i})}},', file=output)
    print("};", file=output)
