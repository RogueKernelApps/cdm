#!/usr/bin/env bash
set -euo pipefail

packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rust_dir=$(dirname "$packaging_dir")
# shellcheck source=versions.env
source "$packaging_dir/versions.env"

fail() {
    printf 'cdm Alpine source container: %s\n' "$*" >&2
    exit 1
}

[[ $# -le 1 ]] || fail "usage: $0 [new-output-directory]"
command -v docker >/dev/null 2>&1 || fail "Docker is required"
output=${1:-"$rust_dir/target/alpine-corresponding-source-$ALPINE_VERSION"}
[[ ! -e "$output" ]] || fail "output already exists: $output"
output_parent=$(dirname "$output")
output_name=$(basename "$output")
[[ "$output_name" =~ ^[A-Za-z0-9][A-Za-z0-9+_.-]*$ ]] \
    || fail "unsafe output directory name: $output_name"
mkdir -p "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd)

docker run --rm \
    --env HOST_UID="$(id -u)" \
    --env HOST_GID="$(id -g)" \
    --env OUTPUT_NAME="$output_name" \
    --volume "$rust_dir:/src:ro" \
    --volume "$output_parent:/output" \
    "$ALPINE_SOURCE_IMAGE" \
    sh -eu -c '
        apk add --no-cache abuild git python3 su-exec wget >/dev/null
        export HOME=/tmp/cdm-source-builder
        mkdir -p "$HOME"
        chown "$HOST_UID:$HOST_GID" "$HOME"
        exec su-exec "$HOST_UID:$HOST_GID" \
            /src/packaging/fetch-alpine-sources.sh \
            /src/assets/alpine-rootfs.lock.json "/output/$OUTPUT_NAME"
    '

python3 "$packaging_dir/verify-alpine-sources.py" verify \
    "$rust_dir/assets/alpine-rootfs.lock.json" "$output"
