#!/usr/bin/env bash
# Build and export the exact static guest-init artifact consumed by build.rs.

prepare_guest_init() {
    local target=$1 output_dir=$2 architecture binary provenance digest
    case "$target" in
        aarch64-apple-darwin|aarch64-unknown-linux-gnu) architecture=aarch64 ;;
        x86_64-unknown-linux-gnu) architecture=x86_64 ;;
        *) fail "unsupported guest-init package target: $target" ;;
    esac
    mkdir -p "$output_dir"
    binary=$(
        RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.90.0} \
            "$rust_dir/guest-init/build-static.sh" "$architecture" "$output_dir"
    )
    provenance="$binary.provenance.json"
    [[ -x "$binary" ]] || fail "guest-init build did not produce an executable: $binary"
    [[ -f "$provenance" ]] || fail "guest-init build did not produce provenance: $provenance"
    digest=$(sha256 "$binary")
    python3 - "$binary" "$provenance" "$digest" "${architecture}-unknown-linux-musl" <<'PY'
import json
from pathlib import Path
import sys

binary, provenance, digest, target = sys.argv[1:]
document = json.loads(Path(provenance).read_text(encoding="utf-8"))
artifact = document.get("artifact", {})
if artifact.get("sha256") != digest:
    raise SystemExit("guest-init provenance digest does not match the artifact")
if artifact.get("target") != target:
    raise SystemExit("guest-init provenance target does not match the package target")
if artifact.get("size") != Path(binary).stat().st_size:
    raise SystemExit("guest-init provenance size does not match the artifact")
PY
    export CDM_GUEST_INIT_BIN=$binary
    export CDM_GUEST_INIT_SHA256=$digest
    export CDM_GUEST_INIT_PROVENANCE=$provenance
}

install_guest_init_evidence() {
    local package=$1
    mkdir -p "$package/libexec/cdm" "$package/share/cdm"
    install -m 0555 "$CDM_GUEST_INIT_BIN" "$package/libexec/cdm/cdm-guest-init"
    install -m 0444 "$CDM_GUEST_INIT_PROVENANCE" \
        "$package/share/cdm/guest-init.provenance.json"
}

verify_guest_init_evidence() {
    local package=$1 target=$2 architecture binary provenance
    case "$target" in
        aarch64-apple-darwin|aarch64-unknown-linux-gnu) architecture=aarch64 ;;
        x86_64-unknown-linux-gnu) architecture=x86_64 ;;
        *) fail "unsupported guest-init verification target: $target" ;;
    esac
    binary="$package/libexec/cdm/cdm-guest-init"
    provenance="$package/share/cdm/guest-init.provenance.json"
    [[ -x "$binary" ]] || fail "missing packaged guest-init artifact"
    [[ -f "$provenance" ]] || fail "missing packaged guest-init provenance"
    python3 - "$binary" "$provenance" "$(sha256 "$binary")" \
        "${architecture}-unknown-linux-musl" <<'PY'
import json
from pathlib import Path
import sys

binary, provenance, digest, target = sys.argv[1:]
document = json.loads(Path(provenance).read_text(encoding="utf-8"))
artifact = document.get("artifact", {})
assert artifact.get("sha256") == digest, "packaged guest-init digest mismatch"
assert artifact.get("target") == target, "packaged guest-init target mismatch"
assert artifact.get("size") == Path(binary).stat().st_size, "packaged guest-init size mismatch"
PY
}
