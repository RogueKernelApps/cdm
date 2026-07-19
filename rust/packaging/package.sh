#!/usr/bin/env bash
set -euo pipefail

packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rust_dir=$(dirname "$packaging_dir")
# shellcheck source=versions.env
source "$packaging_dir/versions.env"
# shellcheck source=guest-init.sh
source "$packaging_dir/guest-init.sh"

command=${1:-release}
dist_dir=${CDM_DIST_DIR:-"$rust_dir/target/dist"}
work_dir=${CDM_PACKAGE_WORK_DIR:-"$rust_dir/target/package-work"}
download_dir="$work_dir/downloads"
runtime_archive=''
source_archive=''
alpine_source_dir=''
cdm_binary=''

fail() {
    printf 'cdm package: %s\n' "$*" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

macos_build_path() {
    if command -v ld.lld >/dev/null 2>&1; then
        printf '%s\n' "$PATH"
        return
    fi
    if command -v brew >/dev/null 2>&1; then
        local lld_bin
        lld_bin="$(brew --prefix lld 2>/dev/null)/bin"
        [[ -x "$lld_bin/ld.lld" ]] && {
            printf '%s:%s\n' "$lld_bin" "$PATH"
            return
        }
    fi
    fail "libkrun requires ld.lld; install lld or put ld.lld on PATH"
}

macos_libclang_dir() {
    if command -v llvm-config >/dev/null 2>&1; then
        llvm-config --libdir
        return
    fi
    if command -v brew >/dev/null 2>&1; then
        local llvm_lib
        llvm_lib="$(brew --prefix llvm 2>/dev/null)/lib"
        [[ -f "$llvm_lib/libclang.dylib" ]] && {
            printf '%s\n' "$llvm_lib"
            return
        }
    fi
    fail "libkrun requires libclang; install LLVM or set LLVM's bin directory on PATH"
}

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

write_checksum() {
    local archive=$1
    printf '%s  %s\n' "$(sha256 "$archive")" "$(basename "$archive")" \
        > "$archive.sha256"
}

create_archive() {
    local source=$1 archive=$2 root_name=$3
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} \
        python3 "$packaging_dir/create-archive.py" "$source" "$archive" "$root_name"
}

download() {
    local url=$1 destination=$2 expected=$3
    mkdir -p "$(dirname "$destination")"
    if [[ ! -f "$destination" || "$(sha256 "$destination")" != "$expected" ]]; then
        command -p rm -f "$destination"
        curl --fail --location --silent --show-error "$url" --output "$destination"
    fi
    [[ "$(sha256 "$destination")" == "$expected" ]] || fail "checksum mismatch: $destination"
}

cdm_version() {
    awk -F '"' '/^version = / { print $2; exit }' "$rust_dir/Cargo.toml"
}

source_revision() {
    git -C "$rust_dir" rev-parse HEAD 2>/dev/null \
        || fail "release provenance requires a Git source revision"
}

resolve_alpine_source_dir() {
    local candidate=${CDM_ALPINE_SOURCE_DIR:-}
    [[ -n "$candidate" ]] || return 1
    [[ -d "$candidate" ]] \
        || fail "Alpine corresponding-source directory not found: $candidate"
    alpine_source_dir=$(CDPATH= cd -- "$candidate" && pwd -P)
    python3 "$packaging_dir/verify-alpine-sources.py" verify \
        "$rust_dir/assets/alpine-rootfs.lock.json" "$alpine_source_dir" \
        || fail "Alpine corresponding-source verification failed"
}

release_preflight() {
    local target identity
    target=$(host_target)
    if [[ "$target" == *apple-darwin ]]; then
        identity=${CDM_CODESIGN_IDENTITY:-}
        [[ -n "$identity" && "$identity" != "-" ]] \
            || fail "macOS release requires a non-ad-hoc CDM_CODESIGN_IDENTITY"
    fi
    [[ -f "$rust_dir/../LICENSE" && ! -L "$rust_dir/../LICENSE" ]] \
        || fail "production release requires an owner-approved root LICENSE"
    python3 - "$rust_dir" <<'PY' \
        || fail "production release requires Cargo license metadata matching the root LICENSE"
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
))
package_id = metadata["resolve"]["root"]
package = next(item for item in metadata["packages"] if item["id"] == package_id)
if package.get("license"):
    raise SystemExit(0)
license_file = package.get("license_file")
if not license_file or pathlib.Path(license_file).resolve() != (root.parent / "LICENSE").resolve():
    raise SystemExit(1)
PY
    [[ -n "${CDM_ALPINE_SOURCE_DIR:-}" ]] \
        || fail "production release requires a verified CDM_ALPINE_SOURCE_DIR"
    resolve_alpine_source_dir
    if [[ -n "$(git -C "$rust_dir" status --porcelain --untracked-files=normal)" ]]; then
        fail "production releases require a clean Git worktree"
    fi
}

build_cdm() {
    local target=$1 encoded=${CARGO_ENCODED_RUSTFLAGS:-} separator=$'\x1f' cargo_home
    local cargo_target_dir="$work_dir/cargo-target-$target"
    cargo_home=${CARGO_HOME:-${HOME:+$HOME/.cargo}}
    encoded+="${encoded:+$separator}--remap-path-prefix=$rust_dir=/usr/src/cdm"
    if [[ -n "$cargo_home" ]]; then
        encoded+="$separator--remap-path-prefix=$cargo_home=/usr/src/cargo"
    fi
    if [[ -n "${HOME:-}" ]]; then
        encoded+="$separator--remap-path-prefix=$HOME=/home/cdm-builder"
    fi
    [[ -n "$cargo_target_dir" ]] || fail "empty package Cargo target directory"
    command -p rm -rf -- "$cargo_target_dir"
    (
        unset RUSTFLAGS
        export CARGO_INCREMENTAL=0 CARGO_ENCODED_RUSTFLAGS="$encoded"
        export CARGO_TARGET_DIR="$cargo_target_dir"
        cargo build --locked --manifest-path "$rust_dir/Cargo.toml" --release --features vm
    )
    cdm_binary="$cargo_target_dir/release/cdm"
    [[ -x "$cdm_binary" ]] || fail "fresh Cargo build did not produce CDM"
}

host_target() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    case "$os:$arch" in
        Darwin:arm64) echo aarch64-apple-darwin ;;
        Linux:x86_64) echo x86_64-unknown-linux-gnu ;;
        Linux:aarch64|Linux:arm64) echo aarch64-unknown-linux-gnu ;;
        Darwin:*) fail "VM releases support macOS 14+ on Apple silicon only" ;;
        *) fail "unsupported VM release host: $os $arch" ;;
    esac
}

extract_tar() {
    local archive=$1 destination=$2
    command -p rm -rf "$destination"
    mkdir -p "$destination"
    tar -xf "$archive" -C "$destination" --strip-components=1
}

prepare_build_sources() {
    local krun_source="$download_dir/libkrun-v$LIBKRUN_VERSION.tar.gz"
    local fw_source="$download_dir/libkrunfw-v$LIBKRUNFW_VERSION.tar.gz"

    download "https://github.com/libkrun/libkrun/archive/refs/tags/v$LIBKRUN_VERSION.tar.gz" \
        "$krun_source" "$LIBKRUN_SOURCE_SHA256"
    download "https://github.com/libkrun/libkrunfw/archive/refs/tags/v$LIBKRUNFW_VERSION.tar.gz" \
        "$fw_source" "$LIBKRUNFW_SOURCE_SHA256"
}

prepare_corresponding_sources() {
    local kernel_source="$download_dir/linux-$LINUX_VERSION.tar.xz"
    prepare_build_sources
    download "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz" \
        "$kernel_source" "$LINUX_SOURCE_SHA256"
}

apply_relative_firmware_patch() {
    local source=$1
    require patch
    patch --batch --forward -d "$source" -p1 \
        < "$packaging_dir/libkrun-relative-firmware.patch"
}

build_macos_runtime() {
    local prefix=$1 build_path libclang_dir
    local fw_archive="$download_dir/libkrunfw-prebuilt-aarch64-v$LIBKRUNFW_VERSION.tgz"
    local fw_source="$work_dir/libkrunfw-build"
    local krun_source="$work_dir/libkrun-build"

    require install_name_tool
    require codesign
    require pkg-config
    require make
    require cargo
    require curl
    require xz
    build_path=$(macos_build_path)
    libclang_dir=$(macos_libclang_dir)

    download "https://github.com/libkrun/libkrunfw/releases/download/v$LIBKRUNFW_VERSION/libkrunfw-prebuilt-aarch64.tgz" \
        "$fw_archive" "$LIBKRUNFW_PREBUILT_AARCH64_SHA256"
    prepare_build_sources
    extract_tar "$fw_archive" "$fw_source"
    MACOSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET make -C "$fw_source"
    MACOSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET \
        make -C "$fw_source" PREFIX="$prefix" install
    extract_tar "$download_dir/libkrun-v$LIBKRUN_VERSION.tar.gz" "$krun_source"
    apply_relative_firmware_patch "$krun_source"
    PATH="$build_path" LIBCLANG_PATH="$libclang_dir" \
        MACOSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET \
        make -C "$krun_source" PREFIX="$prefix" all
    PATH="$build_path" LIBCLANG_PATH="$libclang_dir" \
        MACOSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET \
        make -C "$krun_source" PREFIX="$prefix" install
}

build_linux_runtime() {
    local prefix=$1 target=$2 arch archive checksum fw_source krun_source
    arch=${target%%-*}
    archive="$download_dir/libkrunfw-$arch-v$LIBKRUNFW_VERSION.tgz"
    fw_source="$work_dir/libkrunfw-runtime"
    krun_source="$work_dir/libkrun-build"

    require patchelf
    require pkg-config
    require make
    require cargo
    require curl

    case "$arch" in
        x86_64) checksum=$LIBKRUNFW_LINUX_X86_64_SHA256 ;;
        aarch64) checksum=$LIBKRUNFW_LINUX_AARCH64_SHA256 ;;
        *) fail "unsupported Linux VM architecture: $arch" ;;
    esac

    download "https://github.com/libkrun/libkrunfw/releases/download/v$LIBKRUNFW_VERSION/libkrunfw-$arch.tgz" \
        "$archive" "$checksum"
    prepare_build_sources
    command -p rm -rf "$fw_source"
    mkdir -p "$fw_source"
    tar -xf "$archive" -C "$fw_source"
    extract_tar "$download_dir/libkrun-v$LIBKRUN_VERSION.tar.gz" "$krun_source"
    apply_relative_firmware_patch "$krun_source"
    make -C "$krun_source" PREFIX="$prefix" all

    mkdir -p "$prefix/lib64"
    install -m 755 "$fw_source/lib64/libkrunfw.so.$LIBKRUNFW_VERSION" \
        "$prefix/lib64/libkrunfw.so.$LIBKRUNFW_ABI"
    ln -sf "libkrunfw.so.$LIBKRUNFW_ABI" "$prefix/lib64/libkrunfw.so"
    make -C "$krun_source" PREFIX="$prefix" install
}

copy_licenses() {
    local package=$1 krun_source=$2 fw_source=$3
    local licenses="$package/share/licenses" alpine_source=${alpine_source_dir:--}
    mkdir -p "$licenses/libkrun" "$licenses/libkrunfw"
    cp "$krun_source/LICENSE" "$licenses/libkrun/Apache-2.0.txt"
    cp "$fw_source/LICENSE-GPL-2.0-only" "$licenses/libkrunfw/GPL-2.0-only.txt"
    cp "$fw_source/LICENSE-LGPL-2.1-only" "$licenses/libkrunfw/LGPL-2.1-only.txt"
    python3 "$packaging_dir/package-alpine-licenses.py" \
        "$rust_dir/assets/alpine-rootfs.lock.json" "$alpine_source" "$licenses/alpine" \
        || fail "could not package embedded Alpine license material"
    cp "$packaging_dir/THIRD_PARTY_NOTICES.md" "$package/THIRD_PARTY_NOTICES.md"
    if [[ -f "$rust_dir/../LICENSE" && ! -L "$rust_dir/../LICENSE" ]]; then
        cp "$rust_dir/../LICENSE" "$package/LICENSE"
    fi
}

verify_first_party_license() {
    local package=$1
    if [[ -f "$rust_dir/../LICENSE" && ! -L "$rust_dir/../LICENSE" ]]; then
        [[ -f "$package/LICENSE" && ! -L "$package/LICENSE" ]] \
            || fail "missing packaged first-party LICENSE"
        cmp -s "$rust_dir/../LICENSE" "$package/LICENSE" \
            || fail "packaged first-party LICENSE differs from the owner-approved source"
    elif [[ "$command" == release ]]; then
        fail "production release is missing the owner-approved root LICENSE"
    fi

    python3 - "$rust_dir" "$package" "$command" <<'PY' \
        || fail "SPDX SBOM first-party license metadata does not match the package"
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
package_dir = pathlib.Path(sys.argv[2]).resolve()
production = sys.argv[3] == "release"
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
))
package_id = metadata["resolve"]["root"]
crate = next(item for item in metadata["packages"] if item["id"] == package_id)
expected = crate.get("license")
license_file = crate.get("license_file")
if not expected and license_file:
    if pathlib.Path(license_file).resolve() == (root.parent / "LICENSE").resolve():
        expected = "LicenseRef-CDM"

sbom = json.loads((package_dir / "SBOM.spdx.json").read_text(encoding="utf-8"))
cdm = next((item for item in sbom.get("packages", []) if item.get("name") == "cdm"), None)
if cdm is None or cdm.get("licenseDeclared") != (expected or "NOASSERTION"):
    raise SystemExit(1)

packaged_license = package_dir / "LICENSE"
files = {item.get("fileName"): item for item in sbom.get("files", [])}
if packaged_license.exists():
    digest = hashlib.sha256(packaged_license.read_bytes()).hexdigest()
    checksums = files.get("./LICENSE", {}).get("checksums", [])
    if {item.get("algorithm"): item.get("checksumValue") for item in checksums}.get("SHA256") != digest:
        raise SystemExit(1)
elif production:
    raise SystemExit(1)
PY
}

codesign_with_retry() {
    local attempt=1
    while ! codesign "$@"; do
        (( attempt >= 3 )) && return 1
        printf 'cdm package: codesign attempt %d failed; retrying secure timestamp\n' \
            "$attempt" >&2
        sleep $((attempt * 2))
        attempt=$((attempt + 1))
    done
}

rewrite_macos_package() {
    local package=$1
    local binary="$package/bin/cdm" library_dir="$package/lib/cdm"
    local linked_krun linked_firmware mach_o replacement
    linked_krun=$(otool -L "$binary" | awk '/libkrun\.[0-9]+\.dylib/ {print $1; exit}')
    [[ -n "$linked_krun" ]] || fail "CDM does not link to libkrun"

    install_name_tool -change "$linked_krun" "@rpath/libkrun.1.dylib" "$binary"
    for mach_o in "$binary" "$library_dir/libkrun.1.dylib"; do
        while IFS= read -r rpath; do
            [[ "$rpath" == /* ]] && install_name_tool -delete_rpath "$rpath" "$mach_o"
        done < <(otool -l "$mach_o" | awk '/cmd LC_RPATH/{getline; getline; print $2}')
    done
    if ! otool -l "$binary" | grep -q '@executable_path/../lib/cdm'; then
        install_name_tool -add_rpath '@executable_path/../lib/cdm' "$binary"
    fi
    install_name_tool -id '@rpath/libkrun.1.dylib' "$library_dir/libkrun.1.dylib"
    install_name_tool -id "@rpath/libkrunfw.$LIBKRUNFW_ABI.dylib" \
        "$library_dir/libkrunfw.$LIBKRUNFW_ABI.dylib"

    # Rewrite the complete bundled edge, not just the executable's first
    # dependency. libkrun normally records the build-prefix path to libkrunfw.
    for mach_o in "$binary" "$library_dir/libkrun.1.dylib"; do
        while IFS= read -r linked_firmware; do
            [[ -n "$linked_firmware" ]] || continue
            if [[ "$mach_o" == "$binary" ]]; then
                replacement="@rpath/libkrunfw.$LIBKRUNFW_ABI.dylib"
            else
                replacement="@loader_path/libkrunfw.$LIBKRUNFW_ABI.dylib"
            fi
            install_name_tool -change "$linked_firmware" "$replacement" "$mach_o"
        done < <(otool -L "$mach_o" | awk '/libkrunfw\.[0-9]+\.dylib/ {print $1}')
    done

    local identity=${CDM_CODESIGN_IDENTITY:--}
    local sign_options=(--force --sign "$identity")
    if [[ "$identity" != "-" ]]; then
        sign_options+=(--options runtime --timestamp)
    fi
    codesign_with_retry "${sign_options[@]}" \
        "$library_dir/libkrunfw.$LIBKRUNFW_ABI.dylib"
    codesign_with_retry "${sign_options[@]}" "$library_dir/libkrun.1.dylib"
    codesign_with_retry "${sign_options[@]}" \
        --entitlements "$packaging_dir/macos-hypervisor-entitlements.plist" "$binary"
}

rewrite_linux_package() {
    local package=$1
    local binary="$package/bin/cdm" library_dir="$package/lib/cdm"
    local linked_krun
    linked_krun=$(patchelf --print-needed "$binary" | awk '/libkrun\.so/ {print; exit}')
    [[ -n "$linked_krun" ]] || fail "CDM does not link to libkrun"
    patchelf --replace-needed "$linked_krun" libkrun.so.1 "$binary"
    patchelf --set-rpath '$ORIGIN/../lib/cdm' "$binary"
    patchelf --set-soname libkrun.so.1 "$library_dir/libkrun.so.1"
    patchelf --set-rpath '$ORIGIN' "$library_dir/libkrun.so.1"
    patchelf --set-soname "libkrunfw.so.$LIBKRUNFW_ABI" \
        "$library_dir/libkrunfw.so.$LIBKRUNFW_ABI"
}

verify_package() {
    local package=$1 target=$2 require_complete=${3:-1}
    local binary="$package/bin/cdm" library_dir="$package/lib/cdm"
    [[ -x "$binary" ]] || fail "missing packaged CDM binary"
    [[ -x "$package/install.sh" ]] || fail "missing package installer"
    [[ -f "$package/THIRD_PARTY_NOTICES.md" ]] || fail "missing third-party notices"
    [[ -f "$package/SBOM.spdx.json" ]] || fail "missing SPDX SBOM"
    python3 -m json.tool "$package/SBOM.spdx.json" >/dev/null || fail "invalid SPDX SBOM"
    local alpine_verify=(--verify)
    [[ "$require_complete" == 1 ]] && alpine_verify+=(--require-source-notices)
    python3 "$packaging_dir/package-alpine-licenses.py" "${alpine_verify[@]}" \
        "$rust_dir/assets/alpine-rootfs.lock.json" "$package/share/licenses/alpine" \
        || fail "invalid or incomplete embedded Alpine legal material"
    verify_first_party_license "$package"
    verify_guest_init_evidence "$package" "$target"
    ! LC_ALL=C grep -aFq "$rust_dir" "$binary" \
        || fail "packaged CDM binary leaks the repository build path"

    if [[ "$target" == *apple-darwin ]]; then
        [[ -f "$library_dir/libkrun.1.dylib" ]] || fail "missing bundled libkrun"
        [[ -f "$library_dir/libkrunfw.$LIBKRUNFW_ABI.dylib" ]] || fail "missing bundled libkrunfw"
        otool -L "$binary" | grep -q '@rpath/libkrun.1.dylib' || fail "libkrun is not rpath-relative"
        otool -l "$binary" | grep -q '@executable_path/../lib/cdm' || fail "package rpath is missing"
        ! otool -l "$binary" | awk '/cmd LC_RPATH/{getline; getline; print $2}' | grep -q '^/' \
            || fail "package contains an absolute rpath"
        codesign --verify --strict "$binary"
        codesign --verify --strict "$library_dir/libkrun.1.dylib"
        codesign --verify --strict "$library_dir/libkrunfw.$LIBKRUNFW_ABI.dylib"
    else
        [[ -f "$library_dir/libkrun.so.1" ]] || fail "missing bundled libkrun"
        [[ -f "$library_dir/libkrunfw.so.$LIBKRUNFW_ABI" ]] || fail "missing bundled libkrunfw"
        [[ "$(patchelf --print-rpath "$binary")" == '$ORIGIN/../lib/cdm' ]] \
            || fail "package rpath is not relocatable"
    fi
    python3 "$packaging_dir/verify-runtime.py" "$target" "$package" \
        || fail "runtime dependency, entitlement, or relocation verification failed"
}

verify_release_signature() {
    local package=$1 target=$2 details
    [[ "$target" == *apple-darwin ]] || return 0
    details=$(codesign -dv --verbose=4 "$package/bin/cdm" 2>&1)
    ! grep -q 'Signature=adhoc' <<<"$details" || fail "release binary is ad-hoc signed"
    grep -q '^Authority=' <<<"$details" || fail "release binary has no signing authority"
    codesign -d --entitlements :- "$package/bin/cdm" 2>/dev/null \
        | grep -q 'com.apple.security.hypervisor' \
        || fail "release binary is missing the Hypervisor entitlement"
}

notarize_macos_package() {
    local package=$1 archive=$2 target=$3 profile=${CDM_NOTARY_PROFILE:-}
    local submission result temporary_zip
    [[ -n "$profile" ]] || return 0
    [[ "$target" == *apple-darwin ]] \
        || fail "CDM_NOTARY_PROFILE is valid only for a macOS release"
    require xcrun
    require ditto
    temporary_zip="$work_dir/$(basename "$package").notary.zip"
    result="$archive.notarization.json"
    submission="$result.tmp"
    command -p rm -f "$temporary_zip" "$submission"
    ditto -c -k --keepParent "$package" "$temporary_zip"
    xcrun notarytool submit "$temporary_zip" --keychain-profile "$profile" \
        --wait --output-format json > "$submission"
    python3 - "$submission" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
if result.get("status") != "Accepted":
    raise SystemExit(f"notarization was not accepted: {result.get('status', 'unknown')}")
PY
    mv -f "$submission" "$result"
    command -p rm -f "$temporary_zip"
}

write_release_provenance() {
    local runtime=$1 sources=$2 target=$3 version=$4 revision output firmware_uri firmware_sha
    local package source_epoch rustc_version cargo_version make_version
    revision=$(source_revision)
    output="$dist_dir/cdm-$version-$target.provenance.intoto.json"
    package=${runtime%.tar.gz}
    [[ -d "$package" ]] || fail "release package directory not found for provenance: $package"
    source_epoch=${SOURCE_DATE_EPOCH:-0}
    rustc_version=$(rustc --version)
    cargo_version=$(cargo --version)
    make_version=$(make --version | sed -n '1p')
    case "$target" in
        aarch64-apple-darwin)
            firmware_uri="https://github.com/libkrun/libkrunfw/releases/download/v$LIBKRUNFW_VERSION/libkrunfw-prebuilt-aarch64.tgz"
            firmware_sha=$LIBKRUNFW_PREBUILT_AARCH64_SHA256
            ;;
        aarch64-unknown-linux-gnu)
            firmware_uri="https://github.com/libkrun/libkrunfw/releases/download/v$LIBKRUNFW_VERSION/libkrunfw-aarch64.tgz"
            firmware_sha=$LIBKRUNFW_LINUX_AARCH64_SHA256
            ;;
        x86_64-unknown-linux-gnu)
            firmware_uri="https://github.com/libkrun/libkrunfw/releases/download/v$LIBKRUNFW_VERSION/libkrunfw-x86_64.tgz"
            firmware_sha=$LIBKRUNFW_LINUX_X86_64_SHA256
            ;;
        *) fail "unsupported provenance target: $target" ;;
    esac
    python3 "$packaging_dir/generate-provenance.py" \
        --output "$output" \
        --target "$target" \
        --version "$version" \
        --source-revision "$revision" \
        --source-date-epoch "$source_epoch" \
        --subject "$runtime" \
        --subject "$sources" \
        --material "file:Cargo.lock=$(sha256 "$rust_dir/Cargo.lock")" \
        --material "file:Cargo.toml=$(sha256 "$rust_dir/Cargo.toml")" \
        --material "file:rust-toolchain.toml=$(sha256 "$rust_dir/rust-toolchain.toml")" \
        --material "file:build.rs=$(sha256 "$rust_dir/build.rs")" \
        --material "file:packaging/libkrun-relative-firmware.patch=$(sha256 "$packaging_dir/libkrun-relative-firmware.patch")" \
        --material "file:LICENSE=$(sha256 "$package/LICENSE")" \
        --material "file:guest-init/Cargo.lock=$(sha256 "$rust_dir/guest-init/Cargo.lock")" \
        --material "file:guest-init/Cargo.toml=$(sha256 "$rust_dir/guest-init/Cargo.toml")" \
        --evidence "SBOM.spdx.json=$(sha256 "$package/SBOM.spdx.json")" \
        --evidence "guest-init.provenance.json=$(sha256 "$package/share/cdm/guest-init.provenance.json")" \
        --tool "cargo=$cargo_version" \
        --tool "make=$make_version" \
        --tool "rustc=$rustc_version" \
        --material "https://github.com/libkrun/libkrun/archive/refs/tags/v$LIBKRUN_VERSION.tar.gz=$LIBKRUN_SOURCE_SHA256" \
        --material "https://github.com/libkrun/libkrunfw/archive/refs/tags/v$LIBKRUNFW_VERSION.tar.gz=$LIBKRUNFW_SOURCE_SHA256" \
        --material "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz=$LINUX_SOURCE_SHA256" \
        --material "$firmware_uri=$firmware_sha" \
        --material "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/aarch64/alpine-minirootfs-$ALPINE_VERSION-aarch64.tar.gz=$ALPINE_AARCH64_SHA256" \
        --material "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86_64/alpine-minirootfs-$ALPINE_VERSION-x86_64.tar.gz=$ALPINE_X86_64_SHA256" \
        --material "file:alpine-sources.manifest.json=$(sha256 "$alpine_source_dir/alpine-sources.manifest.json")"
    write_checksum "$output"
    printf '%s\n' "$output"
}

package_runtime() {
    local target version prefix package archive krun_source fw_source
    target=$(host_target)
    version=$(cdm_version)
    prefix="$work_dir/prefix-$target"
    package="$dist_dir/cdm-$version-$target"
    archive="$package.tar.gz"

    if [[ -z "$alpine_source_dir" && -n "${CDM_ALPINE_SOURCE_DIR:-}" ]]; then
        resolve_alpine_source_dir
    fi

    command -p rm -rf "$prefix" "$package" "$archive"
    mkdir -p "$prefix" "$package/bin" "$package/lib/cdm"
    prepare_guest_init "$target" "$work_dir/guest-init-$target"

    if [[ "$target" == *apple-darwin ]]; then
        build_macos_runtime "$prefix"
        export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
        export LIBKRUNFW_LIB_DIR="$prefix/lib"
        export MACOSX_DEPLOYMENT_TARGET
        build_cdm "$target"
        install -m 755 "$cdm_binary" "$package/bin/cdm"
        install -m 755 "$prefix/lib/libkrun.1.dylib" "$package/lib/cdm/libkrun.1.dylib"
        install -m 755 "$prefix/lib/libkrunfw.$LIBKRUNFW_ABI.dylib" \
            "$package/lib/cdm/libkrunfw.$LIBKRUNFW_ABI.dylib"
    else
        build_linux_runtime "$prefix" "$target"
        export PKG_CONFIG_PATH="$prefix/lib64/pkgconfig"
        build_cdm "$target"
        install -m 755 "$cdm_binary" "$package/bin/cdm"
        install -m 755 "$prefix/lib64/libkrun.so.1" "$package/lib/cdm/libkrun.so.1"
        install -m 755 "$prefix/lib64/libkrunfw.so.$LIBKRUNFW_ABI" \
            "$package/lib/cdm/libkrunfw.so.$LIBKRUNFW_ABI"
    fi

    install_guest_init_evidence "$package"

    krun_source="$work_dir/libkrun-build"
    fw_source="$work_dir/libkrunfw-license-source-$target"
    extract_tar "$download_dir/libkrunfw-v$LIBKRUNFW_VERSION.tar.gz" "$fw_source"
    copy_licenses "$package" "$krun_source" "$fw_source"
    cp "$packaging_dir/install.sh" "$package/install.sh"
    chmod +x "$package/install.sh"
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} \
        python3 "$packaging_dir/generate-sbom.py" "$target" "$package/SBOM.spdx.json"

    if [[ "$target" == *apple-darwin ]]; then
        rewrite_macos_package "$package"
    else
        rewrite_linux_package "$package"
    fi
    if [[ "$command" == release ]]; then
        verify_package "$package" "$target" 1
    else
        verify_package "$package" "$target" 0
    fi

    create_archive "$package" "$archive" "$(basename "$package")"
    write_checksum "$archive"
    if [[ "$command" == release ]]; then
        verify_release_signature "$package" "$target"
        notarize_macos_package "$package" "$archive" "$target"
    fi
    runtime_archive=$archive
    printf '%s\n' "$archive"
}

package_sources() {
    local target archive staging
    target=$(host_target)
    if [[ -z "$alpine_source_dir" && -n "${CDM_ALPINE_SOURCE_DIR:-}" ]]; then
        resolve_alpine_source_dir
    fi
    prepare_corresponding_sources
    staging="$work_dir/source-package"
    archive="$dist_dir/cdm-vm-sources-libkrun-$LIBKRUN_VERSION-libkrunfw-$LIBKRUNFW_VERSION-$target.tar.gz"
    if [[ -n "$alpine_source_dir" ]]; then
        case "$alpine_source_dir/" in
            "$staging/"* ) fail "Alpine source payload may not be inside package staging" ;;
        esac
        case "$staging/" in
            "$alpine_source_dir/"* ) fail "package staging may not be inside the Alpine source payload" ;;
        esac
    fi
    command -p rm -rf "$staging" "$archive"
    mkdir -p "$staging" "$dist_dir"
    cp "$download_dir/libkrun-v$LIBKRUN_VERSION.tar.gz" "$staging/"
    cp "$packaging_dir/libkrun-relative-firmware.patch" "$staging/"
    cp "$download_dir/libkrunfw-v$LIBKRUNFW_VERSION.tar.gz" "$staging/"
    cp "$download_dir/linux-$LINUX_VERSION.tar.xz" "$staging/"
    cp "$rust_dir/assets/alpine-rootfs.lock.json" "$staging/"
    cp "$rust_dir/assets/alpine-minirootfs-$ALPINE_VERSION-aarch64.tar.gz" "$staging/"
    cp "$rust_dir/assets/alpine-minirootfs-$ALPINE_VERSION-x86_64.tar.gz" "$staging/"
    if [[ -n "$alpine_source_dir" ]]; then
        python3 "$packaging_dir/verify-alpine-sources.py" verify \
            "$rust_dir/assets/alpine-rootfs.lock.json" "$alpine_source_dir"
        cp -R "$alpine_source_dir" "$staging/alpine-corresponding-source"
    fi
    cat > "$staging/MANIFEST.txt" <<EOF
CDM VM source companion

libkrun v$LIBKRUN_VERSION
  SHA-256 $LIBKRUN_SOURCE_SHA256
CDM package-relative libkrun firmware lookup patch
  SHA-256 $(sha256 "$packaging_dir/libkrun-relative-firmware.patch")
libkrunfw v$LIBKRUNFW_VERSION
  SHA-256 $LIBKRUNFW_SOURCE_SHA256
Linux $LINUX_VERSION
  SHA-256 $LINUX_SOURCE_SHA256
Alpine minirootfs $ALPINE_VERSION (AArch64 binary archive)
  SHA-256 $ALPINE_AARCH64_SHA256
Alpine minirootfs $ALPINE_VERSION (x86_64 binary archive)
  SHA-256 $ALPINE_X86_64_SHA256

The libkrunfw source archive contains the kernel configuration and patches.
The Linux archive contains the corresponding upstream kernel source.
The Alpine archives are the exact embedded binary root filesystems and the lock
records their installed source-package/build-commit identities.
EOF
    if [[ -n "$alpine_source_dir" ]]; then
        cat >> "$staging/MANIFEST.txt" <<EOF
The alpine-corresponding-source directory was verified against that lock. It
contains each exact aports APKBUILD directory and every checksum-verified
upstream distfile fetched by Alpine abuild.
EOF
    else
        cat >> "$staging/MANIFEST.txt" <<EOF
Alpine corresponding source is not included. This standalone source helper is
incomplete and must not accompany a redistributed runtime. Production release
refuses this state.
EOF
    fi
    create_archive "$staging" "$archive" "$(basename "$staging")"
    write_checksum "$archive"
    source_archive=$archive
    printf '%s\n' "$archive"
}

case "$command" in
    release)
        release_preflight
        mkdir -p "$dist_dir"
        package_runtime
        package_sources
        write_release_provenance "$runtime_archive" "$source_archive" \
            "$(host_target)" "$(cdm_version)"
        ;;
    runtime)
        mkdir -p "$dist_dir"
        package_runtime
        ;;
    sources)
        mkdir -p "$dist_dir"
        package_sources
        ;;
    verify)
        [[ $# -eq 3 ]] || fail "usage: $0 verify <package-directory> <target-triple>"
        verify_package "$2" "$3" 1
        ;;
    verify-runtime)
        [[ $# -eq 3 ]] || fail "usage: $0 verify-runtime <package-directory> <target-triple>"
        verify_package "$2" "$3" 0
        ;;
    *)
        fail "usage: $0 [release|runtime|sources|verify|verify-runtime <package-directory> <target-triple>]"
        ;;
esac
