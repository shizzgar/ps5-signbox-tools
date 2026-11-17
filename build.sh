#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$project_dir/core/vendor/modules.txt" ]]; then
    unzip -q "$project_dir/upstream/vendor-source.zip" -d "$project_dir"
fi
build_dir="$(mkdir -p "${PS5_BUILD_DIR:-$project_dir/.build}" && cd "${PS5_BUILD_DIR:-$project_dir/.build}" && pwd)"
out_dir="$(mkdir -p "${PS5_OUTPUT_DIR:-$project_dir/elf}" && cd "${PS5_OUTPUT_DIR:-$project_dir/elf}" && pwd)"
jobs="${PS5_BUILD_JOBS:-4}"

download() {
    local url="$1" file="$2" checksum="$3"
    if [[ ! -f "$file" ]]; then
        curl -fsSL --retry 2 --max-time 300 "$url" -o "$file.part"
        mv "$file.part" "$file"
    fi
    printf '%s  %s\n' "$checksum" "$file" | sha256sum -c -
}

if [[ -z "${PS5_PAYLOAD_SDK:-}" ]]; then
    sdk_zip="$build_dir/ps5-payload-sdk.zip"
    download https://github.com/ps5-payload-dev/sdk/releases/download/v0.45/ps5-payload-sdk.zip \
        "$sdk_zip" 5fac64093d0e3e69f2584ce7935f24f703f622d9681f1495c85b9f00d1291a2c
    if [[ ! -x "$build_dir/ps5-payload-sdk/bin/prospero-clang" ]]; then
        unzip -q -o "$sdk_zip" -d "$build_dir"
    fi
    PS5_PAYLOAD_SDK="$build_dir/ps5-payload-sdk"
fi
if [[ ! -x "$PS5_PAYLOAD_SDK/bin/prospero-clang" ]]; then
    printf 'Invalid PS5_PAYLOAD_SDK: %s\n' "$PS5_PAYLOAD_SDK" >&2
    exit 1
fi

if [[ -z "${PS5_PATCHED_GO_ROOT:-}" ]]; then
    if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
        printf 'Set PS5_PATCHED_GO_ROOT to a patched Go 1.27.1 for your host.\n' >&2
        exit 1
    fi
    go_archive="$build_dir/go1.27.1.linux-amd64.tar.gz"
    download https://go.dev/dl/go1.27.1.linux-amd64.tar.gz \
        "$go_archive" 63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
    PS5_PATCHED_GO_ROOT="$build_dir/goroot"
    if [[ ! -f "$PS5_PATCHED_GO_ROOT/.ps5-ready" ]]; then
        if [[ -e "$PS5_PATCHED_GO_ROOT" ]]; then
            printf 'Use a fresh PS5_BUILD_DIR or set PS5_PATCHED_GO_ROOT to the patched Go tree.\n' >&2
            exit 1
        fi
        go_stage="$(mktemp -d "$build_dir/go-stage.XXXXXX")"
        tar -xzf "$go_archive" --strip-components=1 -C "$go_stage"
        patch --batch -d "$go_stage" -p1 <"$project_dir/upstream/go1.27.1-ps5.patch"
        cp "$go_stage/bin/go" "$go_stage/bin/go-bootstrap"
        env GOROOT="$go_stage" GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local \
            "$go_stage/bin/go-bootstrap" install -p "$jobs" cmd/go cmd/link
        touch "$go_stage/.ps5-ready"
        mv "$go_stage" "$PS5_PATCHED_GO_ROOT"
    fi
fi

export GOROOT="$(cd "$PS5_PATCHED_GO_ROOT" && pwd)" GOTOOLCHAIN=local
export GOCACHE="${GOCACHE:-$build_dir/gocache}" GOMODCACHE="${GOMODCACHE:-$build_dir/gomodcache}"
export GOTMPDIR="$build_dir/gotmp"
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"

(
    cd "$project_dir/core"
    env GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 "$GOROOT/bin/go" build \
        -p "$jobs" -mod=vendor -buildvcs=false -trimpath -buildmode=pie \
        -tags 'with_gvisor,with_utls,badlinkname,tfogo_checklinkname0' \
        -ldflags '-s -w -checklinkname=0 -X runtime.godebugDefault=multipathtcp=0 -X github.com/sagernet/sing-box/constant.Version=1.14.4' \
        -o "$build_dir/proxy-go.bin" .
)

sdk="$(cd -- "$PS5_PAYLOAD_SDK" && pwd)"
compiler="$sdk/bin/prospero-clang"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export PATH="$sdk/bin:$PATH"

if [[ -n "${PS5_MICROHTTPD_DIR:-}" ]]; then
    microhttpd="$(cd -- "$PS5_MICROHTTPD_DIR" && pwd)"
    headers="$microhttpd/include"
    library="$microhttpd/lib/libmicrohttpd.a"
else
    mkdir "$work/microhttpd"
    tar -xzf "$project_dir/upstream/libmicrohttpd-1.0.1.tar.gz" --strip-components=1 -C "$work/microhttpd"
    (
        cd "$work/microhttpd"
        CC="$compiler" AR=ar NM=nm RANLIB=ranlib CFLAGS="-O2" \
            ./configure --host=x86_64-pc-freebsd12 --disable-shared --enable-static \
            --disable-https --disable-curl --disable-examples
        make -C src/microhttpd -j"${PS5_BUILD_JOBS:-4}"
    )
    headers="$work/microhttpd/src/include"
    library="$work/microhttpd/src/microhttpd/.libs/libmicrohttpd.a"
fi

python3 "$project_dir/embed-assets.py" "$work/assets.h"
sources=(main.c panel.c process.c trace.c relay.c check.c report.c diagnostics.c service.c webview.c webview-imports.c orbit-image.c orbit-run.c)
for index in "${!sources[@]}"; do
    sources[index]="$project_dir/${sources[index]}"
done
(
    cd "$build_dir"
    shim_flags=(-Os -Wall -Wextra -Werror -ffreestanding -fPIC -fno-builtin -fno-unwind-tables
        -mgeneral-regs-only -fno-asynchronous-unwind-tables)
    "$compiler" "${shim_flags[@]}" -c "$project_dir/orbit-connect.c" -o orbit-connect.o
    "$sdk/bin/prospero-lld" --static -T "$project_dir/orbit-connect.ld" \
        -o orbit-connect.elf orbit-connect.o
    objcopy -O binary -j .text -j .hook_boot -j .hook_data orbit-connect.elf orbit-connect.bin
    "$compiler" "${shim_flags[@]}" -DPS5_WEBVIEW_SHIM -c "$project_dir/orbit-connect.c" -o webview-connect.o
    "$sdk/bin/prospero-lld" --static -T "$project_dir/webview-connect.ld" \
        -o webview-connect.elf webview-connect.o
    objcopy -O binary -j .text -j .hook_data webview-connect.elf webview-connect.bin
    "$compiler" -O2 -Wall -Wextra -Werror -o orbit-probe.elf "$project_dir/orbit-probe.c"
    "$compiler" -O2 -Wall -Wextra -Werror \
        -o proxy-worker.elf "$project_dir/worker.c" "$project_dir/goload.c" \
        "$project_dir/relay.c" "$project_dir/report.c"
    python3 -c 'from pathlib import Path; image = Path("proxy-worker.elf").read_bytes(); assert image.count(b"PS5NET-WORKER-21") == 1 and b"PS5NET-WORKER-21" + bytes(18) in image, "Invalid worker launch record"'
    "$compiler" -O2 -Wall -Wextra -Werror -pthread -I"$work" -I"$headers" \
        -o "$out_dir/ps5-network-v21.elf" "${sources[@]}" "$library"
)
(
    cd "$out_dir"
    sha256sum ps5-network-v21.elf > SHA256SUMS.txt
)
