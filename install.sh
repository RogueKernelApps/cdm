#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

repository=RogueKernelApps/cdm
release_root="https://github.com/$repository/releases"
temp_dir=''

fail() {
    printf 'cdm install: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: install.sh [PREFIX]

Downloads the latest CDM release for this operating system and architecture.
The default prefix is $HOME/.local. Set CDM_INSTALL_VERSION to install a
specific release, for example CDM_INSTALL_VERSION=v0.1.5.
EOF
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        fail "required command not found: shasum or sha256sum"
    fi
}

detect_platform() {
    local os=${1:-} architecture=${2:-}
    [[ -n "$os" ]] || os=$(uname -s)
    [[ -n "$architecture" ]] || architecture=$(uname -m)
    case "$os:$architecture" in
        Darwin:arm64|Darwin:aarch64)
            platform=macos-arm64
            target=aarch64-apple-darwin
            ;;
        Linux:x86_64|Linux:amd64)
            platform=linux-x86_64
            target=x86_64-unknown-linux-gnu
            ;;
        Linux:arm64|Linux:aarch64)
            platform=linux-arm64
            target=aarch64-unknown-linux-gnu
            ;;
        Darwin:*) fail "macOS releases require Apple silicon" ;;
        *) fail "unsupported platform: $os $architecture" ;;
    esac
}

download() {
    local url=$1 output=$2
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --output "$output" "$url"
}

resolve_version() {
    local requested=${CDM_INSTALL_VERSION:-} latest_url
    if [[ -n "$requested" ]]; then
        tag=$requested
        [[ "$tag" == v* ]] || tag="v$tag"
    else
        latest_url=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
            --location --output /dev/null --write-out '%{url_effective}' \
            "$release_root/latest")
        tag=${latest_url##*/}
    fi
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] \
        || fail "release returned an invalid version tag: $tag"
    version=${tag#v}
}

cleanup() {
    local status=$?
    if [[ -n "$temp_dir" ]]; then
        case "$temp_dir" in
            "$tmp_root"/cdm-install.*) command -p rm -rf -- "$temp_dir" ;;
            *) printf 'cdm install: refusing unsafe cleanup path: %s\n' "$temp_dir" >&2 ;;
        esac
    fi
    return "$status"
}

verify_archive() {
    local archive=$1 checksums=$2 name expected actual matches
    name=${archive##*/}
    matches=$(awk -v name="$name" '$2 == name { count += 1; digest = $1 } END {
        if (count != 1) exit 1
        print digest
    }' "$checksums") || fail "SHA256SUMS does not contain exactly one entry for $name"
    expected=$matches
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "invalid SHA-256 for $name"
    actual=$(sha256 "$archive")
    [[ "$actual" == "$expected" ]] || fail "checksum mismatch for $name"
}

extract_archive() {
    local archive=$1 destination=$2 package_name=$3 member
    while IFS= read -r member; do
        [[ -n "$member" ]] || continue
        case "$member" in
            /*) fail "release archive contains an absolute path" ;;
        esac
        case "/$member/" in
            *'/../'*|*'/./'*) fail "release archive contains an unsafe path" ;;
        esac
        case "$member" in
            "$package_name"|"$package_name"/*) ;;
            *) fail "release archive contains an unexpected top-level path" ;;
        esac
    done < <(tar -tzf "$archive")
    tar -xzf "$archive" -C "$destination"
}

main() {
    local prefix archive_name package_name archive checksums installer
    [[ $# -le 1 ]] || fail "too many arguments"
    case "${1:-}" in
        -h|--help) usage; return 0 ;;
    esac
    prefix=${1:-${CDM_INSTALL_PREFIX:-${HOME:?HOME is required}/.local}}
    [[ -n "$prefix" ]] || fail "installation prefix must not be empty"

    for command_name in awk curl mktemp tar uname; do
        require_command "$command_name"
    done
    detect_platform
    resolve_version

    tmp_root=${TMPDIR:-/tmp}
    tmp_root=${tmp_root%/}
    [[ "$tmp_root" == /* ]] || fail "TMPDIR must be absolute"
    temp_dir=$(mktemp -d "$tmp_root/cdm-install.XXXXXX") \
        || fail "could not create a temporary directory"
    [[ -n "$temp_dir" && "$temp_dir" == "$tmp_root"/cdm-install.* ]] \
        || fail "mktemp returned an unsafe path"
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    archive_name="cdm-$version-$platform.tar.gz"
    package_name="cdm-$version-$target"
    archive="$temp_dir/$archive_name"
    checksums="$temp_dir/SHA256SUMS"
    download "$release_root/download/$tag/SHA256SUMS" "$checksums"
    download "$release_root/download/$tag/$archive_name" "$archive"
    verify_archive "$archive" "$checksums"
    extract_archive "$archive" "$temp_dir" "$package_name"

    installer="$temp_dir/$package_name/install.sh"
    [[ -f "$installer" && ! -L "$installer" && -x "$installer" ]] \
        || fail "release package does not contain a safe installer"
    "$installer" install "$prefix"
}

if [[ ${CDM_INSTALL_TEST_LIBRARY:-0} != 1 ]]; then
    main "$@"
fi
