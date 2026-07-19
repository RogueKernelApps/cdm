#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
toolchain=${RUSTUP_TOOLCHAIN:-1.90}

(cd "$here" && RUSTUP_TOOLCHAIN="$toolchain" cargo fmt --check)
(cd "$here" && RUSTUP_TOOLCHAIN="$toolchain" cargo test --locked --all-targets)
(cd "$here" && RUSTUP_TOOLCHAIN="$toolchain" cargo clippy --locked --all-targets -- -D warnings)

python3 -c 'import pathlib; p=pathlib.Path("write-provenance.py"); compile(p.read_text(), str(p), "exec")' \
    2>/dev/null || python3 -c "import pathlib; p=pathlib.Path('$here/write-provenance.py'); compile(p.read_text(), str(p), 'exec')"
python3 -c 'import json,pathlib; json.loads(pathlib.Path("schema-v2.json").read_text())' \
    2>/dev/null || python3 -c "import json,pathlib; json.loads(pathlib.Path('$here/schema-v2.json').read_text())"

tmp_dir=$here/target/package-contract-$$
cleanup() {
    case "$tmp_dir" in
        "$here"/target/package-contract-*) command -p rm -rf -- "$tmp_dir" ;;
        *) echo "refusing unsafe guest-init test cleanup: $tmp_dir" >&2; exit 1 ;;
    esac
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$tmp_dir"
printf binary > "$tmp_dir/cdm-guest-init-aarch64"
python3 "$here/write-provenance.py" \
    "$tmp_dir/cdm-guest-init-aarch64" \
    aarch64-unknown-linux-musl \
    "$here/Cargo.lock"
cp "$tmp_dir/cdm-guest-init-aarch64.provenance.json" "$tmp_dir/first.provenance.json"
python3 "$here/write-provenance.py" \
    "$tmp_dir/cdm-guest-init-aarch64" \
    aarch64-unknown-linux-musl \
    "$here/Cargo.lock"
cmp "$tmp_dir/first.provenance.json" "$tmp_dir/cdm-guest-init-aarch64.provenance.json"
python3 -c 'import hashlib,json,pathlib,sys; data=json.loads(pathlib.Path(sys.argv[1]).read_text()); assert data["schema"] == 1; assert data["artifact"]["target"] == "aarch64-unknown-linux-musl"; assert data["artifact"]["sha256"] == hashlib.sha256(b"binary").hexdigest(); assert {item["path"] for item in data["inputs"]} >= {"Cargo.lock", "src/lib.rs", "src/linux.rs", "src/main.rs"}' \
    "$tmp_dir/cdm-guest-init-aarch64.provenance.json"

if "$here/build-static.sh" unsupported "$tmp_dir" > /dev/null 2>&1; then
    echo "guest-init build accepted an unsupported architecture" >&2
    exit 1
fi

echo "guest-init tests passed"
