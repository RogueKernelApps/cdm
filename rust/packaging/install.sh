#!/usr/bin/env bash
set -euo pipefail

# The installer may be invoked through sudo. Never execute package-manager or
# user-controlled PATH shims with installer privileges.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
manifest_relative=lib/cdm/install-manifest.sha256
installer_uid=$(id -u)
umask 022

fail() {
    printf 'cdm installer: %s\n' "$*" >&2
    exit 1
}

make_transaction() {
    local template=$1
    if [[ ${CDM_TEST_MKTEMP_RESULT+x} == x ]]; then
        printf '%s' "$CDM_TEST_MKTEMP_RESULT"
    else
        mktemp -d "$template"
    fi
}

promote() {
    local source=$1 destination=$2
    if [[ -n ${CDM_TEST_FAIL_DEST:-} && "$destination" == "$CDM_TEST_FAIL_DEST" ]]; then
        return 73
    fi
    mv -f "$source" "$destination"
}

usage() {
    cat <<'EOF'
Usage: install.sh [install|verify|uninstall] [PREFIX]
       install.sh [PREFIX]

The default command is install and the default prefix is $HOME/.local.
EOF
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

path_metadata() {
    local path=$1
    if stat -f '%u %p %l' -- "$path" >/dev/null 2>&1; then
        stat -f '%u %p %l' -- "$path"
    else
        stat -c '%u %a %h' -- "$path"
    fi
}

validate_safe_directory() {
    local path=$1 owner mode links mode_value
    [[ -d "$path" && ! -L "$path" ]] || fail "unsafe directory in installation prefix: $path"
    read -r owner mode links < <(path_metadata "$path") \
        || fail "cannot inspect installation directory: $path"
    [[ "$owner" == "$installer_uid" || "$owner" == 0 ]] \
        || fail "installation directory has an unsafe owner: $path"
    mode_value=$((8#$mode))
    if (( (mode_value & 8#022) != 0 )); then
        # Conventional temporary roots such as /tmp are safe ancestors when
        # root owns them and the sticky bit prevents cross-user replacement.
        (( owner == 0 && (mode_value & 8#1000) != 0 )) \
            || fail "installation directory is writable by another user: $path"
    fi
    [[ "$links" =~ ^[0-9]+$ && "$links" -ge 1 ]] \
        || fail "installation directory has invalid link metadata: $path"
}

validate_safe_file() {
    local path=$1 label=${2:-file} owner mode links
    [[ -f "$path" && ! -L "$path" ]] || fail "unsafe $label: $path"
    read -r owner mode links < <(path_metadata "$path") \
        || fail "cannot inspect $label: $path"
    [[ "$owner" == "$installer_uid" ]] || fail "$label has an unsafe owner: $path"
    [[ "$links" == 1 ]] || fail "$label has multiple hard links: $path"
}

validate_prefix_spelling() {
    [[ "$prefix" == /* ]] || fail "prefix must be absolute"
    case "/${prefix#/}/" in
        *'//'*) fail "prefix must not contain empty path components" ;;
        *'/./'*|*'/../'*) fail "prefix must not contain dot path components" ;;
    esac
    [[ "$prefix" != / ]] || fail "refusing to use the filesystem root as a prefix"
}

# Validate every existing component without canonicalizing through a symlink.
# Components created here are checked immediately. Because every directory in
# the chain is root/current-user owned and not group/other writable, an
# unprivileged different user cannot swap a checked component before promotion.
prepare_prefix() {
    local create=$1 rest component cursor=/
    validate_prefix_spelling
    rest=${prefix#/}
    while [[ -n "$rest" ]]; do
        component=${rest%%/*}
        if [[ "$rest" == */* ]]; then
            rest=${rest#*/}
        else
            rest=
        fi
        [[ -n "$component" && "$component" != . && "$component" != .. ]] \
            || fail "unsafe prefix component"
        [[ "$cursor" == / ]] && cursor="/$component" || cursor="$cursor/$component"
        if [[ -e "$cursor" || -L "$cursor" ]]; then
            validate_safe_directory "$cursor"
        elif [[ "$create" == 1 ]]; then
            mkdir -- "$cursor" || fail "cannot create installation directory: $cursor"
            validate_safe_directory "$cursor"
        else
            fail "installation prefix does not exist: $cursor"
        fi
    done
}

validate_managed_directories() {
    prepare_prefix 0
    validate_safe_directory "$prefix/bin"
    validate_safe_directory "$prefix/lib"
    validate_safe_directory "$prefix/lib/cdm"
}

prepare_managed_directories() {
    prepare_prefix 1
    local directory
    for directory in "$prefix/bin" "$prefix/lib" "$prefix/lib/cdm"; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            validate_safe_directory "$directory"
        else
            mkdir -- "$directory" || fail "cannot create installation directory: $directory"
            validate_safe_directory "$directory"
        fi
    done
}

valid_owned_path() {
    case "$1" in
        bin/cdm) return 0 ;;
        lib/cdm/*)
            local name=${1#lib/cdm/}
            [[ "$1" != "$manifest_relative" && -n "$name" && "$name" != */* \
                && "$name" != . && "$name" != .. && "$name" != *[!A-Za-z0-9._+-]* ]]
            return
            ;;
        *) return 1 ;;
    esac
}

validate_manifest() {
    local manifest=$1 hash relative count=0
    validate_safe_file "$manifest" "ownership manifest"
    while IFS=$'\t' read -r hash relative; do
        [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || fail "invalid hash in ownership manifest"
        valid_owned_path "$relative" || fail "unsafe path in ownership manifest: $relative"
        count=$((count + 1))
    done < "$manifest"
    [[ "$count" -gt 0 ]] || fail "empty ownership manifest: $manifest"
}

manifest_has() {
    local manifest=$1 wanted=$2 hash relative
    [[ -f "$manifest" ]] || return 1
    while IFS=$'\t' read -r hash relative; do
        [[ "$relative" == "$wanted" ]] && return 0
    done < "$manifest"
    return 1
}

verify_manifest_files() {
    local prefix=$1 manifest=$2 hash relative target actual
    validate_manifest "$manifest"
    while IFS=$'\t' read -r hash relative; do
        target="$prefix/$relative"
        validate_safe_file "$target" "owned file"
        actual=$(sha256 "$target")
        [[ "$actual" == "$hash" ]] || fail "owned file was modified: $target"
    done < "$manifest"
}

parse_arguments() {
    action=install
    prefix=${HOME:?HOME is required}/.local

    case "${1:-}" in
        install|verify|uninstall)
            action=$1
            [[ $# -le 2 ]] || fail "too many arguments"
            [[ $# -lt 2 ]] || prefix=$2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        '')
            [[ $# -eq 0 ]] || fail "invalid arguments"
            ;;
        *)
            # Preserve the original `install.sh PREFIX` interface.
            [[ $# -eq 1 ]] || fail "too many arguments"
            prefix=$1
            ;;
    esac

    [[ -n "$prefix" ]] || fail "prefix must not be empty"
    case "$prefix" in
        /*) ;;
        .) prefix="$(pwd -P)" ;;
        ./*) prefix="$(pwd -P)/${prefix#./}" ;;
        *) prefix="$(pwd -P)/$prefix" ;;
    esac
    while [[ "$prefix" != / && "$prefix" == */ ]]; do
        prefix=${prefix%/}
    done
    validate_prefix_spelling
}

write_package_manifest() {
    local destination=$1 source relative found_library=0
    : > "$destination"

    validate_safe_file "$package_dir/bin/cdm" "packaged CDM binary"
    printf '%s\t%s\n' "$(sha256 "$package_dir/bin/cdm")" bin/cdm >> "$destination"

    for source in "$package_dir"/lib/cdm/*; do
        [[ -e "$source" ]] || continue
        validate_safe_file "$source" "packaged library"
        relative="lib/cdm/${source##*/}"
        valid_owned_path "$relative" || fail "unsafe packaged library path: $relative"
        printf '%s\t%s\n' "$(sha256 "$source")" "$relative" >> "$destination"
        found_library=1
    done
    [[ "$found_library" -eq 1 ]] || fail "package contains no runtime libraries"
    validate_manifest "$destination"
}

install_package() {
    manifest="$prefix/$manifest_relative"
    transaction=''
    new_root=''
    backup_root=''
    new_manifest=''
    promoted_file=''
    old_manifest=''
    committed=0
    local hash relative target source current

    prepare_managed_directories
    transaction=$(make_transaction "$prefix/.cdm-install.XXXXXX") \
        || fail "cannot create installation transaction under $prefix"
    [[ -n "$transaction" && "$transaction" == "$prefix"/.cdm-install.* ]] \
        || fail "mktemp returned an unsafe installation transaction path"
    validate_safe_directory "$transaction"
    new_root="$transaction/new"
    backup_root="$transaction/backup"
    new_manifest="$transaction/new-manifest"
    promoted_file="$transaction/promoted"
    mkdir -p "$new_root/bin" "$new_root/lib/cdm" "$backup_root"
    : > "$promoted_file"

    rollback_install() {
        local status=$? rollback_hash rollback_path
        [[ "$committed" -eq 0 ]] || return "$status"
        set +e
        if [[ -f "$promoted_file" ]]; then
            while IFS= read -r rollback_path; do
                [[ -n "$rollback_path" ]] && command -p rm -f "$prefix/$rollback_path"
            done < "$promoted_file"
        fi
        if [[ -n "$old_manifest" && -f "$old_manifest" ]]; then
            while IFS=$'\t' read -r rollback_hash rollback_path; do
                if [[ -f "$backup_root/$rollback_path" ]]; then
                    mkdir -p "$(dirname "$prefix/$rollback_path")"
                    cp -p "$backup_root/$rollback_path" "$prefix/$rollback_path"
                fi
            done < "$old_manifest"
        fi
        if [[ -f "$backup_root/$manifest_relative" ]]; then
            cp -p "$backup_root/$manifest_relative" "$manifest"
        else
            command -p rm -f "$manifest"
        fi
        command -p rm -rf "$transaction"
        return "$status"
    }
    trap rollback_install EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    write_package_manifest "$new_manifest"
    while IFS=$'\t' read -r hash relative; do
        source="$package_dir/$relative"
        install -m 755 "$source" "$new_root/$relative"
    done < "$new_manifest"

    if [[ -e "$manifest" ]]; then
        validate_manifest "$manifest"
        old_manifest="$transaction/old-manifest"
        cp -p "$manifest" "$old_manifest"
        mkdir -p "$backup_root/$(dirname "$manifest_relative")"
        cp -p "$manifest" "$backup_root/$manifest_relative"
    fi

    # Refuse to overwrite paths not claimed by the previous manifest.
    while IFS=$'\t' read -r hash relative; do
        target="$prefix/$relative"
        if [[ -e "$target" || -L "$target" ]]; then
            [[ -n "$old_manifest" ]] && manifest_has "$old_manifest" "$relative" \
                || fail "destination exists but is not owned by CDM: $target"
            validate_safe_file "$target" "owned destination"
        fi
    done < "$new_manifest"

    # Modified stale paths cannot be deleted safely because CDM no longer owns their content.
    if [[ -n "$old_manifest" ]]; then
        while IFS=$'\t' read -r hash relative; do
            manifest_has "$new_manifest" "$relative" && continue
            target="$prefix/$relative"
            [[ -e "$target" || -L "$target" ]] || continue
            validate_safe_file "$target" "stale owned file"
            current=$(sha256 "$target")
            [[ "$current" == "$hash" ]] || fail "stale owned file was modified: $target"
        done < "$old_manifest"
    fi

    # Back up the complete previous install for best-effort rollback.
    if [[ -n "$old_manifest" ]]; then
        while IFS=$'\t' read -r hash relative; do
            target="$prefix/$relative"
            [[ -f "$target" ]] || continue
            mkdir -p "$backup_root/$(dirname "$relative")"
            cp -p "$target" "$backup_root/$relative"
        done < "$old_manifest"
    fi

    # Promote libraries before the executable so an interrupted upgrade never exposes
    # a new executable with an old runtime. Each rename stays on the prefix filesystem.
    validate_managed_directories
    while IFS=$'\t' read -r hash relative; do
        [[ "$relative" == bin/cdm ]] && continue
        printf '%s\n' "$relative" >> "$promoted_file"
        promote "$new_root/$relative" "$prefix/$relative"
    done < "$new_manifest"
    printf '%s\n' bin/cdm >> "$promoted_file"
    promote "$new_root/bin/cdm" "$prefix/bin/cdm"

    if [[ -n "$old_manifest" ]]; then
        while IFS=$'\t' read -r hash relative; do
            manifest_has "$new_manifest" "$relative" || command -p rm -f "$prefix/$relative"
        done < "$old_manifest"
    fi
    install -m 644 "$new_manifest" "$transaction/manifest-ready"
    promote "$transaction/manifest-ready" "$manifest"

    committed=1
    trap - EXIT HUP INT TERM
    command -p rm -rf "$transaction"
    printf 'Installed CDM to %s\n' "$prefix"
    printf 'Ensure %s/bin is on PATH.\n' "$prefix"
}

verify_installation() {
    local manifest="$prefix/$manifest_relative"
    validate_managed_directories
    verify_manifest_files "$prefix" "$manifest"
    printf 'Verified CDM installation at %s\n' "$prefix"
}

uninstall_package() {
    manifest="$prefix/$manifest_relative"
    transaction=''
    backup_root=''
    committed=0
    local hash relative target
    validate_managed_directories
    verify_manifest_files "$prefix" "$manifest"
    transaction=$(make_transaction "$prefix/.cdm-uninstall.XXXXXX") \
        || fail "cannot create uninstall transaction under $prefix"
    [[ -n "$transaction" && "$transaction" == "$prefix"/.cdm-uninstall.* ]] \
        || fail "mktemp returned an unsafe uninstall transaction path"
    validate_safe_directory "$transaction"
    backup_root="$transaction/backup"
    mkdir -p "$backup_root/$(dirname "$manifest_relative")"
    cp -p "$manifest" "$backup_root/$manifest_relative"
    while IFS=$'\t' read -r hash relative; do
        mkdir -p "$backup_root/$(dirname "$relative")"
        cp -p "$prefix/$relative" "$backup_root/$relative"
    done < "$manifest"

    rollback_uninstall() {
        local status=$? rollback_hash rollback_path
        [[ "$committed" -eq 0 ]] || return "$status"
        set +e
        while IFS=$'\t' read -r rollback_hash rollback_path; do
            mkdir -p "$(dirname "$prefix/$rollback_path")"
            cp -p "$backup_root/$rollback_path" "$prefix/$rollback_path"
        done < "$backup_root/$manifest_relative"
        cp -p "$backup_root/$manifest_relative" "$manifest"
        command -p rm -rf "$transaction"
        return "$status"
    }
    trap rollback_uninstall EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    while IFS=$'\t' read -r hash relative; do
        command -p rm -f "$prefix/$relative"
    done < "$manifest"
    command -p rm -f "$manifest"
    rmdir "$prefix/bin" "$prefix/lib/cdm" "$prefix/lib" 2>/dev/null || true

    committed=1
    trap - EXIT HUP INT TERM
    command -p rm -rf "$transaction"
    printf 'Uninstalled CDM from %s\n' "$prefix"
}

parse_arguments "$@"
case "$action" in
    install) install_package ;;
    verify) verify_installation ;;
    uninstall) uninstall_package ;;
esac
