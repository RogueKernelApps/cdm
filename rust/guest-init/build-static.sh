#!/bin/sh
set -eu

usage() {
    echo "usage: $0 <aarch64|x86_64> <output-directory>" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
arch=$1
output_dir=$2
case "$arch" in
    aarch64|x86_64) ;;
    *) usage ;;
esac

target="${arch}-unknown-linux-musl"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)

if ! rustup target list --installed | grep -qx "$target"; then
    echo "cdm-guest-init: missing Rust target $target; install it explicitly with: rustup target add $target" >&2
    exit 1
fi

# A host `cc` selects the host linker (for example Apple's `ld`) and cannot
# link a Linux ELF when this runs on macOS or for another Linux architecture.
# Rust ships LLD with the active toolchain, so select it explicitly rather than
# requiring a separately installed cross-linker.
sysroot=$(rustc --print sysroot)
host=$(rustc -vV | awk '/^host:/ { print $2; exit }')
rust_lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
if [ ! -x "$rust_lld" ]; then
    echo "cdm-guest-init: active Rust toolchain has no rust-lld at $rust_lld" >&2
    exit 1
fi
linker_variable="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_LINKER"

(
    cd "$here"
    env "$linker_variable=$rust_lld" CARGO_INCREMENTAL=0 \
        cargo build --locked --release --target "$target" >&2
)

binary="$here/target/$target/release/cdm-guest-init"
destination="$output_dir/cdm-guest-init-$arch"
install -m 0755 "$binary" "$destination"

if command -v file >/dev/null 2>&1 && ! file "$destination" | grep -Eq 'statically linked|static-pie linked'; then
    echo "cdm-guest-init: $destination is not statically linked" >&2
    command -p rm -f -- "$destination"
    exit 1
fi

python3 "$here/write-provenance.py" "$destination" "$target" "$here/Cargo.lock"
echo "$destination"
