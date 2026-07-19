#!/bin/sh
set -eu

die() {
    printf 'cdm Alpine sources: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || die "usage: $0 <alpine-rootfs.lock.json> <new-output-directory>"
lock=$1
output=$2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier="$script_dir/verify-alpine-sources.py"

[ -f /etc/alpine-release ] || die "this acquisition tool must run on Alpine Linux"
[ -f "$lock" ] || die "rootfs lock not found: $lock"
[ ! -e "$output" ] || die "output already exists: $output"
for command in abuild git python3; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

expected_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["alpine_version"])' "$lock")
actual_version=$(cat /etc/alpine-release)
[ "$actual_version" = "$expected_version" ] \
    || die "Alpine $expected_version is required; running $actual_version"
aports_branch=${expected_version%.*}-stable

mkdir -p "$output/packages"
output_marker="$output/.cdm-alpine-source-acquisition"
printf 'cdm-alpine-source-v1\n' > "$output_marker"
cleanup_output() {
    if [ -f "$output_marker" ] \
        && [ "$(cat "$output_marker")" = 'cdm-alpine-source-v1' ]; then
        command -p rm -rf -- "$output"
    else
        die "refusing to remove unmarked output after failure: $output"
    fi
}
work=$(mktemp -d "${TMPDIR:-/tmp}/cdm-alpine-sources.XXXXXX")
cleanup() {
    [ ! -e "$output_marker" ] || cleanup_output
    case "$work" in
        "${TMPDIR:-/tmp}"/cdm-alpine-sources.*) command -p rm -rf -- "$work" ;;
        *) die "refusing unsafe temporary cleanup: $work" ;;
    esac
}
trap cleanup EXIT HUP INT TERM

if ! git clone --quiet --branch "$aports_branch" --single-branch \
    https://gitlab.alpinelinux.org/alpine/aports.git "$work/aports"; then
    cleanup_output
    die "could not clone Alpine aports $aports_branch"
fi

failed=0
python3 "$verifier" expected "$lock" > "$work/expected.tsv"
tab=$(printf '\t')
fetch_sources() {
    source_dir=$1
    destination=$2
    attempt=0
    while ! (cd "$source_dir" && SRCDEST="$destination" abuild fetch); do
        attempt=$((attempt + 1))
        [ "$attempt" -ge 3 ] && return 1
        sleep $((attempt * 2))
    done
}
while IFS="$tab" read -r package versions commit; do
    [ -n "$package" ] || continue
    if ! git -C "$work/aports" cat-file -e "$commit^{commit}" 2>/dev/null; then
        git -C "$work/aports" fetch --quiet origin "$commit" \
            || { failed=1; break; }
    fi
    git -C "$work/aports" checkout --quiet --detach --force "$commit" \
        || { failed=1; break; }

    source_dir=''
    for repository in main community testing; do
        candidate="$work/aports/$repository/$package"
        if [ -f "$candidate/APKBUILD" ]; then
            source_dir=$candidate
            break
        fi
    done
    [ -n "$source_dir" ] || { printf 'missing APKBUILD for %s at %s\n' "$package" "$commit" >&2; failed=1; break; }

    (cd "$source_dir" && abuild validate) \
        || { failed=1; break; }
    # APKBUILDs are evaluated by abuild without nounset and may reference
    # abuild-provided variables at file scope. Validate first with the official
    # parser, then read only the declared identity in the same shell mode.
    actual=$(cd "$source_dir" && sh -e -c '. ./APKBUILD; printf "%s\t%s-r%s" "$pkgname" "$pkgver" "$pkgrel"')
    actual_name=${actual%%"$tab"*}
    actual_version=${actual#*"$tab"}
    case ",$versions," in
        *",$actual_version,"*) ;;
        *) printf 'APKBUILD version mismatch for %s: expected %s, found %s\n' "$package" "$versions" "$actual_version" >&2; failed=1; break ;;
    esac
    [ "$actual_name" = "$package" ] \
        || { printf 'APKBUILD package mismatch: expected %s, found %s\n' "$package" "$actual_name" >&2; failed=1; break; }

    package_dir="$output/packages/$package"
    mkdir -p "$package_dir/aports" "$package_dir/distfiles"
    cp -R "$source_dir/." "$package_dir/aports/"

    # Alpine's authoritative tools download every remote source declared by this
    # exact APKBUILD, then independently verify all declared checksums.
    fetch_sources "$source_dir" "$package_dir/distfiles" \
        || { failed=1; break; }
    (cd "$source_dir" && SRCDEST="$package_dir/distfiles" abuild verify) \
        || { failed=1; break; }
    python3 - "$package_dir/receipt.json" "$package" "$versions" "$commit" <<'PY'
import json, pathlib, sys
path, package, versions, commit = sys.argv[1:]
payload = {
    "source_package": package,
    "versions": sorted(versions.split(",")),
    "build_commit": commit,
}
pathlib.Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
done < "$work/expected.tsv"

if [ "$failed" -ne 0 ]; then
    cleanup_output
    die "source acquisition failed"
fi
command -p rm -f -- "$output_marker"
python3 "$verifier" write-manifest "$lock" "$output" \
    || { printf 'cdm-alpine-source-v1\n' > "$output_marker"; cleanup_output; die "manifest generation failed"; }
python3 "$verifier" verify "$lock" "$output" \
    || { printf 'cdm-alpine-source-v1\n' > "$output_marker"; cleanup_output; die "independent source verification failed"; }
printf 'Verified Alpine corresponding-source payload: %s\n' "$output"
