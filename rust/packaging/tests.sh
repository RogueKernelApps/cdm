#!/usr/bin/env bash
set -euo pipefail

packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=versions.env
source "$packaging_dir/versions.env"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

[[ "$LIBKRUN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid libkrun version"
[[ "$LIBKRUNFW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid libkrunfw version"
[[ "$MACOSX_DEPLOYMENT_TARGET" == 14.0 ]] || fail "unexpected macOS deployment target"

for checksum in \
    "$LIBKRUN_SOURCE_SHA256" \
    "$LIBKRUNFW_PREBUILT_AARCH64_SHA256" \
    "$LIBKRUNFW_LINUX_AARCH64_SHA256" \
    "$LIBKRUNFW_LINUX_X86_64_SHA256" \
    "$LIBKRUNFW_SOURCE_SHA256" \
    "$LINUX_SOURCE_SHA256" \
    "$ALPINE_AARCH64_SHA256" \
    "$ALPINE_X86_64_SHA256"; do
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || fail "invalid SHA-256: $checksum"
done

[[ "$(sha256 "$packaging_dir/../assets/alpine-minirootfs-$ALPINE_VERSION-aarch64.tar.gz")" == "$ALPINE_AARCH64_SHA256" ]] \
    || fail "bundled AArch64 Alpine rootfs checksum mismatch"
[[ "$(sha256 "$packaging_dir/../assets/alpine-minirootfs-$ALPINE_VERSION-x86_64.tar.gz")" == "$ALPINE_X86_64_SHA256" ]] \
    || fail "bundled x86_64 Alpine rootfs checksum mismatch"
python3 -m json.tool "$packaging_dir/../assets/alpine-rootfs.lock.json" >/dev/null \
    || fail "invalid Alpine rootfs manifest"

bash -n "$packaging_dir/package.sh"
bash -n "$packaging_dir/guest-init.sh"
bash -n "$packaging_dir/install.sh"
bash -n "$packaging_dir/check-upstream.sh"
bash -n "$packaging_dir/prepare-alpine-sources-container.sh"
sh -n "$packaging_dir/fetch-alpine-sources.sh"
python3 -c 'compile(open(__import__("sys").argv[1], encoding="utf-8").read(), __import__("sys").argv[1], "exec")' \
    "$packaging_dir/create-archive.py"
python3 -c 'compile(open(__import__("sys").argv[1], encoding="utf-8").read(), __import__("sys").argv[1], "exec")' \
    "$packaging_dir/generate-provenance.py"
python3 -c 'compile(open(__import__("sys").argv[1], encoding="utf-8").read(), __import__("sys").argv[1], "exec")' \
    "$packaging_dir/verify-runtime.py"
python3 -c 'compile(open(__import__("sys").argv[1], encoding="utf-8").read(), __import__("sys").argv[1], "exec")' \
    "$packaging_dir/generate-sbom.py"
python3 -c 'compile(open(__import__("sys").argv[1], encoding="utf-8").read(), __import__("sys").argv[1], "exec")' \
    "$packaging_dir/verify-alpine-sources.py"
python3 -c 'compile(open(__import__("sys").argv[1], encoding="utf-8").read(), __import__("sys").argv[1], "exec")' \
    "$packaging_dir/package-alpine-licenses.py"

grep -q '@executable_path/../lib/cdm' "$packaging_dir/package.sh" \
    || fail "macOS package is not executable-relative"
grep -q 'apply_relative_firmware_patch' "$packaging_dir/package.sh" \
    || fail "libkrun firmware loader is not made package-relative"
grep -q '@loader_path/libkrunfw.5.dylib' "$packaging_dir/libkrun-relative-firmware.patch" \
    || fail "macOS libkrun firmware patch is not loader-relative"
grep -q '\$ORIGIN/libkrunfw.so.5' "$packaging_dir/libkrun-relative-firmware.patch" \
    || fail "Linux libkrun firmware patch is not loader-relative"
grep -q '\$ORIGIN/../lib/cdm' "$packaging_dir/package.sh" \
    || fail "Linux package is not executable-relative"
grep -q 'Do not redistribute' "$packaging_dir/THIRD_PARTY_NOTICES.md" \
    || fail "source-distribution requirement is missing"
grep -q 'LIBKRUN_VERSION' "$packaging_dir/check-upstream.sh" \
    || fail "runtime freshness check does not inspect libkrun"
grep -q 'CARGO_INCREMENTAL=0' "$packaging_dir/package.sh" \
    || fail "release build does not disable Cargo incremental compilation"
grep -q -- '--remap-path-prefix=' "$packaging_dir/package.sh" \
    || fail "release build does not remap build paths"
grep -q 'packaged CDM binary leaks the repository build path' "$packaging_dir/package.sh" \
    || fail "package verification does not reject repository-path leaks"
grep -q 'CDM_NOTARY_PROFILE' "$packaging_dir/package.sh" \
    || fail "optional notarization contract is missing"
grep -Fq 'codesign_with_retry' "$packaging_dir/package.sh" \
    || fail "Developer ID signing does not retry transient timestamp failures"
grep -q 'owner-approved root LICENSE' "$packaging_dir/package.sh" \
    || fail "production release does not gate missing first-party license terms"
grep -q 'packaged first-party LICENSE differs' "$packaging_dir/package.sh" \
    || fail "package verification does not compare the first-party license"
grep -q 'SPDX SBOM first-party license metadata' "$packaging_dir/package.sh" \
    || fail "package verification does not validate first-party SBOM metadata"
grep -q 'generate-provenance.py' "$packaging_dir/package.sh" \
    || fail "release does not generate provenance"
grep -q 'prepare_guest_init' "$packaging_dir/package.sh" \
    || fail "VM package does not build the static guest init"
grep -q 'verify_guest_init_evidence' "$packaging_dir/package.sh" \
    || fail "VM package does not verify guest-init provenance"
grep -q 'verify-runtime.py' "$packaging_dir/package.sh" \
    || fail "package verification does not inspect the runtime dependency closure"
grep -Fq 'command -p rm -rf -- "$cargo_target_dir"' "$packaging_dir/package.sh" \
    || fail "package build does not start with a fresh Cargo target directory"
if grep -Fq '[[ ! -f "$krun_source/target/release/' "$packaging_dir/package.sh"; then
    fail "package build may reuse a stale libkrun build"
fi
grep -q 'CDM_ALPINE_SOURCE_DIR' "$packaging_dir/package.sh" \
    || fail "production release does not require verified Alpine source"
grep -q 'package-alpine-licenses.py' "$packaging_dir/package.sh" \
    || fail "runtime package omits the Alpine legal-material generator"
grep -q -- '--require-source-notices' "$packaging_dir/package.sh" \
    || fail "redistributable package verification permits missing source-derived notices"
grep -q 'share/licenses/alpine/inventory.json' "$packaging_dir/THIRD_PARTY_NOTICES.md" \
    || fail "third-party notices omit the embedded Alpine inventory"
grep -q 'abuild fetch' "$packaging_dir/fetch-alpine-sources.sh" \
    || fail "Alpine source acquisition does not use the official abuild fetch path"
grep -Fq '[ "$attempt" -ge 3 ]' "$packaging_dir/fetch-alpine-sources.sh" \
    || fail "Alpine source acquisition does not bound transient fetch retries"
grep -q 'abuild verify' "$packaging_dir/fetch-alpine-sources.sh" \
    || fail "Alpine source acquisition does not verify upstream checksums"
grep -q 'abuild validate' "$packaging_dir/fetch-alpine-sources.sh" \
    || fail "Alpine source acquisition does not validate each exact APKBUILD"
grep -Fq 'aports_branch=${expected_version%.*}-stable' \
    "$packaging_dir/fetch-alpine-sources.sh" \
    || fail "Alpine source acquisition does not derive the stable aports branch"
grep -A8 '^cleanup()' "$packaging_dir/fetch-alpine-sources.sh" \
    | grep -q 'cleanup_output' \
    || fail "Alpine source acquisition does not remove marked partial output on unexpected exit"
[[ "$ALPINE_SOURCE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] \
    || fail "Alpine source builder image is not digest-pinned"

archive_fixture=$(mktemp -d "${TMPDIR:-/tmp}/cdm-archive-test.XXXXXX")
case "$(CDPATH= cd -- "$archive_fixture" && pwd -P)" in
    "$packaging_dir"|"$packaging_dir"/*) fail "archive fixture resolved inside the repository" ;;
esac
cleanup_archive_fixture() {
    case "$archive_fixture" in
        "${TMPDIR:-/tmp}"/cdm-archive-test.*) command -p rm -rf -- "$archive_fixture" ;;
        *) fail "refusing unsafe archive-fixture cleanup: $archive_fixture" ;;
    esac
}
trap cleanup_archive_fixture EXIT

patch_fixture="$archive_fixture/libkrun/src/libkrun/src"
mkdir -p "$patch_fixture"
cat > "$patch_fixture/lib.rs" <<'EOF'
// preceding source

// krunfw library name for each context
#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.5";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";

#[cfg(feature = "aws-nitro")]
static KRUN_NITRO_DEBUG: Mutex<bool> = Mutex::new(false);
EOF
patch --batch --forward -d "$archive_fixture/libkrun" -p1 \
    < "$packaging_dir/libkrun-relative-firmware.patch" >/dev/null
grep -Fq '@loader_path/libkrunfw.5.dylib' "$patch_fixture/lib.rs" \
    || fail "libkrun relative firmware patch did not apply"

SOURCE_DATE_EPOCH=123 python3 "$packaging_dir/generate-sbom.py" \
    aarch64-apple-darwin "$archive_fixture/SBOM.spdx.json"
python3 - "$packaging_dir/.." "$archive_fixture/SBOM.spdx.json" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1]).resolve()
sbom = json.load(open(sys.argv[2], encoding="utf-8"))
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
))
root_id = metadata["resolve"]["root"]
crate = next(item for item in metadata["packages"] if item["id"] == root_id)
expected = crate.get("license")
if not expected and crate.get("license_file"):
    if pathlib.Path(crate["license_file"]).resolve() == (root.parent / "LICENSE").resolve():
        expected = "LicenseRef-CDM"
cdm = next(item for item in sbom["packages"] if item["name"] == "cdm")
assert cdm["licenseDeclared"] == (expected or "NOASSERTION")
license_path = root.parent / "LICENSE"
files = {item["fileName"]: item for item in sbom.get("files", [])}
if license_path.is_file() and not license_path.is_symlink():
    checksums = files["./LICENSE"]["checksums"]
    actual = next(item["checksumValue"] for item in checksums if item["algorithm"] == "SHA256")
    assert actual == hashlib.sha256(license_path.read_bytes()).hexdigest()
else:
    assert "./LICENSE" not in files
PY
mkdir -p "$archive_fixture/input/sub"
printf 'payload\n' > "$archive_fixture/input/sub/file"
printf '#!/bin/sh\nexit 0\n' > "$archive_fixture/input/tool"
ln -s sub/file "$archive_fixture/input/link"
chmod 700 "$archive_fixture/input" "$archive_fixture/input/sub"
chmod 600 "$archive_fixture/input/sub/file"
chmod 700 "$archive_fixture/input/tool"
(
    umask 077
    SOURCE_DATE_EPOCH=123 python3 "$packaging_dir/create-archive.py" \
        "$archive_fixture/input" "$archive_fixture/one.tar.gz" fixture
)
chmod 777 "$archive_fixture/input" "$archive_fixture/input/sub"
chmod 666 "$archive_fixture/input/sub/file"
chmod 777 "$archive_fixture/input/tool"
SOURCE_DATE_EPOCH=123 python3 "$packaging_dir/create-archive.py" \
    "$archive_fixture/input" "$archive_fixture/two.tar.gz" fixture
[[ "$(sha256 "$archive_fixture/one.tar.gz")" == "$(sha256 "$archive_fixture/two.tar.gz")" ]] \
    || fail "release archives are not reproducible"
python3 - "$archive_fixture/one.tar.gz" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as archive:
    for item in archive:
        assert (item.uid, item.gid, item.uname, item.gname, item.mtime) == (0, 0, "root", "root", 123)
        if item.isdir():
            assert item.mode == 0o755, (item.name, oct(item.mode))
        elif item.issym():
            assert item.mode == 0o777, (item.name, oct(item.mode))
        elif item.isfile():
            expected = 0o755 if item.name.endswith("/tool") else 0o644
            assert item.mode == expected, (item.name, oct(item.mode))
PY

runtime_fixture="$archive_fixture/runtime-fixture"
fake_tools="$archive_fixture/fake-tools"
mkdir -p "$runtime_fixture/bin" "$runtime_fixture/lib/cdm" "$fake_tools"
cat > "$runtime_fixture/bin/cdm" <<'SH'
#!/bin/sh
test "${1:-}" = --version
SH
chmod 755 "$runtime_fixture/bin/cdm"
printf 'krun @loader_path/libkrunfw.5.dylib\n' > "$runtime_fixture/lib/cdm/libkrun.1.dylib"
printf 'firmware\n' > "$runtime_fixture/lib/cdm/libkrunfw.5.dylib"
cat > "$fake_tools/otool" <<'SH'
#!/bin/sh
mode=$1
file=$2
if [ "$mode" = -l ]; then
    case "$file" in
        */bin/cdm) printf 'cmd LC_RPATH\ncmdsize 48\npath @executable_path/../lib/cdm (offset 12)\n' ;;
    esac
elif [ "$mode" = -L ]; then
    printf '%s:\n' "$file"
    case "$file" in
        */bin/cdm) printf '\t@rpath/libkrun.1.dylib (compatibility version 1.0.0, current version 1.0.0)\n' ;;
        */libkrun.1.dylib) printf '\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n' ;;
        */libkrunfw.5.dylib) printf '\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n' ;;
    esac
fi
SH
cat > "$fake_tools/codesign" <<'SH'
#!/bin/sh
if [ "${1:-}" = -d ]; then
    cat <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>
PLIST
fi
SH
chmod 755 "$fake_tools/otool" "$fake_tools/codesign"
PATH="$fake_tools:$PATH" python3 "$packaging_dir/verify-runtime.py" \
    aarch64-apple-darwin "$runtime_fixture"

command -p rm -rf -- "$runtime_fixture" "$fake_tools"
mkdir -p "$runtime_fixture/bin" "$runtime_fixture/lib/cdm" "$fake_tools"
cat > "$runtime_fixture/bin/cdm" <<'SH'
#!/bin/sh
test "${1:-}" = --version
SH
chmod 755 "$runtime_fixture/bin/cdm"
printf 'krun $ORIGIN/libkrunfw.so.5\n' > "$runtime_fixture/lib/cdm/libkrun.so.1"
printf 'firmware\n' > "$runtime_fixture/lib/cdm/libkrunfw.so.5"
cat > "$fake_tools/patchelf" <<'SH'
#!/bin/sh
mode=$1
file=$2
if [ "$mode" = --print-rpath ]; then
    case "$file" in */bin/cdm) printf '$ORIGIN/../lib/cdm\n' ;; *) printf '$ORIGIN\n' ;; esac
elif [ "$mode" = --print-needed ]; then
    case "$file" in
        */bin/cdm) printf 'libkrun.so.1\n' ;;
        */libkrun.so.1) printf 'libc.so.6\n' ;;
    esac
fi
SH
cat > "$fake_tools/ldd" <<'SH'
#!/bin/sh
root=$(CDPATH= cd -- "$(dirname -- "$1")/.." && pwd -P)
printf 'libkrun.so.1 => %s/lib/cdm/libkrun.so.1\n' "$root"
SH
chmod 755 "$fake_tools/patchelf" "$fake_tools/ldd"
PATH="$fake_tools:$PATH" python3 "$packaging_dir/verify-runtime.py" \
    x86_64-unknown-linux-gnu "$runtime_fixture"

PYTHONDONTWRITEBYTECODE=1 python3 - "$packaging_dir/../assets/update-alpine-lock.py" \
    "$archive_fixture/regenerated-alpine-lock.json" <<'PY'
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("update_alpine_lock", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
module.OUTPUT = pathlib.Path(sys.argv[2])
module.main()
PY
cmp "$archive_fixture/regenerated-alpine-lock.json" \
    "$packaging_dir/../assets/alpine-rootfs.lock.json" \
    || fail "Alpine rootfs lock is not a byte-identical regeneration"

mkdir -p "$archive_fixture/alpine-payload/packages/example/aports" \
    "$archive_fixture/alpine-payload/packages/example/distfiles"
cat > "$archive_fixture/alpine-lock.json" <<'JSON'
{
  "schema": 2,
  "alpine_version": "3.21.7",
  "rootfs": [
    {
      "architecture": "aarch64",
      "packages": [
        {
          "source_package": "example",
          "version": "1.2.3-r4",
          "build_commit": "0123456789abcdef0123456789abcdef01234567"
        }
      ]
    },
    {
      "architecture": "x86_64",
      "packages": [
        {
          "source_package": "example",
          "version": "1.2.3-r4",
          "build_commit": "0123456789abcdef0123456789abcdef01234567"
        }
      ]
    }
  ]
}
JSON
cat > "$archive_fixture/alpine-payload/packages/example/receipt.json" <<'JSON'
{
  "build_commit": "0123456789abcdef0123456789abcdef01234567",
  "source_package": "example",
  "versions": [
    "1.2.3-r4"
  ]
}
JSON
printf 'pkgname=example\npkgver=1.2.3\npkgrel=4\n' \
    > "$archive_fixture/alpine-payload/packages/example/aports/APKBUILD"
printf 'source-controlled notice\n' \
    > "$archive_fixture/alpine-payload/packages/example/aports/NOTICE"
ln -s NOTICE \
    "$archive_fixture/alpine-payload/packages/example/aports/NOTICE.link"
printf 'upstream source\n' \
    > "$archive_fixture/alpine-payload/packages/example/distfiles/example-1.2.3.tar.gz"
python3 "$packaging_dir/verify-alpine-sources.py" write-manifest \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload"
python3 "$packaging_dir/verify-alpine-sources.py" verify \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload"
python3 - "$archive_fixture/alpine-payload/alpine-sources.manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
entries = manifest["source_packages"][0]["files"]
link = next(item for item in entries if item["path"].endswith("/NOTICE.link"))
assert link == {
    "path": "packages/example/aports/NOTICE.link",
    "symlink": "NOTICE",
}
PY
cp "$archive_fixture/alpine-payload/alpine-sources.manifest.json" \
    "$archive_fixture/alpine-manifest-first.json"
command -p rm "$archive_fixture/alpine-payload/alpine-sources.manifest.json"
python3 "$packaging_dir/verify-alpine-sources.py" write-manifest \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload"
cmp "$archive_fixture/alpine-manifest-first.json" \
    "$archive_fixture/alpine-payload/alpine-sources.manifest.json" \
    || fail "Alpine source manifest is not deterministic"
command -p rm -f -- "$archive_fixture/alpine-payload/alpine-sources.manifest.json"
ln -s ../../../../outside \
    "$archive_fixture/alpine-payload/packages/example/aports/escape.link"
if python3 "$packaging_dir/verify-alpine-sources.py" write-manifest \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload" \
    >/dev/null 2>&1; then
    fail "Alpine source verifier accepted an escaping symlink"
fi
command -p rm -f -- "$archive_fixture/alpine-payload/packages/example/aports/escape.link"
python3 "$packaging_dir/verify-alpine-sources.py" write-manifest \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload"
mkdir -p "$archive_fixture/alpine-payload/packages/unexpected"
if python3 "$packaging_dir/verify-alpine-sources.py" verify \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload" >/dev/null 2>&1; then
    fail "Alpine source verifier accepted extra package coverage"
fi
command -p rm -rf "$archive_fixture/alpine-payload/packages/unexpected"

# The embedded Alpine filesystem needs a package inventory, canonical texts for
# every declared SPDX license, and exact upstream notices recovered from the
# already-verified corresponding-source payload. Keep this fixture small while
# exercising both a raw notice and a notice inside an upstream archive.
command -p rm -f -- "$archive_fixture/alpine-payload/alpine-sources.manifest.json"
printf 'pkgname=example\npkgver=1.2.3\npkgrel=4\nlicense="MIT AND BSD-2-Clause"\n' \
    > "$archive_fixture/alpine-payload/packages/example/aports/APKBUILD"
printf 'exact aports copyright notice\n' \
    > "$archive_fixture/alpine-payload/packages/example/aports/COPYRIGHT"
mkdir -p "$archive_fixture/upstream-notices/project"
printf 'exact upstream license text\n' \
    > "$archive_fixture/upstream-notices/project/LICENSE"
python3 -c 'import pathlib,tarfile,sys; p=pathlib.Path(sys.argv[1]); t=tarfile.open(sys.argv[2], "w:gz"); t.add(p, arcname="project"); t.close()' \
    "$archive_fixture/upstream-notices/project" \
    "$archive_fixture/alpine-payload/packages/example/distfiles/example-1.2.3.tar.gz"
python3 "$packaging_dir/verify-alpine-sources.py" write-manifest \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload"
python3 -c 'import json,pathlib; p=pathlib.Path(__import__("sys").argv[1]); d=json.loads(p.read_text()); [item.update({"license":"MIT AND BSD-2-Clause","name":"example","architecture":root["architecture"],"apk_checksum":"fixture","description":"fixture","source_url":"https://example.invalid/source"}) for root in d["rootfs"] for item in root["packages"]]; p.write_text(json.dumps(d,indent=2)+"\n")' \
    "$archive_fixture/alpine-lock.json"
# The source verifier is identity-driven, so changing only binary-package
# metadata in the lock does not invalidate the exact source manifest.
python3 "$packaging_dir/package-alpine-licenses.py" \
    "$archive_fixture/alpine-lock.json" \
    "$archive_fixture/alpine-payload" \
    "$archive_fixture/alpine-legal-one"
python3 "$packaging_dir/package-alpine-licenses.py" \
    "$archive_fixture/alpine-lock.json" \
    "$archive_fixture/alpine-payload" \
    "$archive_fixture/alpine-legal-two"
diff -ru "$archive_fixture/alpine-legal-one" "$archive_fixture/alpine-legal-two" \
    || fail "Alpine legal bundle is not deterministic"
[[ -f "$archive_fixture/alpine-legal-one/LICENSES/MIT.txt" ]] \
    || fail "Alpine legal bundle omitted canonical MIT text"
[[ -f "$archive_fixture/alpine-legal-one/LICENSES/BSD-2-Clause.txt" ]] \
    || fail "Alpine legal bundle omitted canonical BSD-2-Clause text"
grep -Rqx 'exact aports copyright notice' \
    "$archive_fixture/alpine-legal-one/upstream-notices" \
    || fail "Alpine legal bundle omitted exact aports notice"
grep -Rqx 'exact upstream license text' \
    "$archive_fixture/alpine-legal-one/upstream-notices" \
    || fail "Alpine legal bundle omitted exact archived upstream notice"
python3 - "$archive_fixture/alpine-legal-one/inventory.json" <<'PY'
import json, sys
inventory = json.load(open(sys.argv[1], encoding="utf-8"))
assert inventory["schema"] == 1
assert inventory["source_verified"] is True
assert inventory["notice_discovery"]["scheme"] == "conventional-legal-filenames-v1"
assert inventory["spdx_license_list_version"] == "3.28.0"
assert inventory["license_ids"] == ["BSD-2-Clause", "MIT"]
assert {item["architecture"] for item in inventory["packages"]} == {"aarch64", "x86_64"}
assert inventory["upstream_notices"]
PY
python3 "$packaging_dir/package-alpine-licenses.py" --verify --require-source-notices \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-legal-one"
python3 "$packaging_dir/package-alpine-licenses.py" \
    "$archive_fixture/alpine-lock.json" - "$archive_fixture/alpine-legal-incomplete"
python3 "$packaging_dir/package-alpine-licenses.py" --verify \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-legal-incomplete"
if python3 "$packaging_dir/package-alpine-licenses.py" --verify --require-source-notices \
    "$archive_fixture/alpine-lock.json" \
    "$archive_fixture/alpine-legal-incomplete" >/dev/null 2>&1; then
    fail "Alpine legal verifier accepted an incomplete redistribution bundle"
fi
notice_to_tamper=$(find "$archive_fixture/alpine-legal-two/upstream-notices" -type f | head -1)
[[ -n "$notice_to_tamper" ]] || fail "Alpine legal fixture contains no notice to tamper"
printf 'tampered\n' >> "$notice_to_tamper"
if python3 "$packaging_dir/package-alpine-licenses.py" --verify --require-source-notices \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-legal-two" \
    >/dev/null 2>&1; then
    fail "Alpine legal verifier accepted a modified upstream notice"
fi
cp -R "$packaging_dir/alpine-license-texts" "$archive_fixture/license-texts-broken"
printf 'tampered\n' >> "$archive_fixture/license-texts-broken/MIT.txt"
if python3 "$packaging_dir/package-alpine-licenses.py" \
    --license-texts "$archive_fixture/license-texts-broken" \
    "$archive_fixture/alpine-lock.json" \
    "$archive_fixture/alpine-payload" \
    "$archive_fixture/alpine-legal-broken" >/dev/null 2>&1; then
    fail "Alpine legal bundle accepted a modified canonical license text"
fi
cp -R "$archive_fixture/alpine-payload" "$archive_fixture/alpine-payload-hostile"
command -p rm -f -- \
    "$archive_fixture/alpine-payload-hostile/alpine-sources.manifest.json"
python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1], "w"); z.writestr("a"*4097+"/LICENSE", "hostile\n"); z.close()' \
    "$archive_fixture/alpine-payload-hostile/packages/example/distfiles/hostile.zip"
python3 "$packaging_dir/verify-alpine-sources.py" write-manifest \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload-hostile"
if python3 "$packaging_dir/package-alpine-licenses.py" \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload-hostile" \
    "$archive_fixture/alpine-legal-unbounded" >/dev/null 2>&1; then
    fail "Alpine legal generator accepted an overlong archive member path"
fi
printf 'tampered\n' >> "$archive_fixture/alpine-payload/packages/example/aports/APKBUILD"
if python3 "$packaging_dir/verify-alpine-sources.py" verify \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload" >/dev/null 2>&1; then
    fail "Alpine source verifier accepted modified source"
fi
if python3 "$packaging_dir/package-alpine-licenses.py" \
    "$archive_fixture/alpine-lock.json" "$archive_fixture/alpine-payload" \
    "$archive_fixture/alpine-legal-from-tampered-source" >/dev/null 2>&1; then
    fail "Alpine legal generator accepted unverified corresponding source"
fi

printf 'runtime' > "$archive_fixture/runtime.tar.gz"
printf 'sources' > "$archive_fixture/sources.tar.gz"
for output in provenance-one.json provenance-two.json; do
    python3 "$packaging_dir/generate-provenance.py" \
        --output "$archive_fixture/$output" \
        --target aarch64-apple-darwin \
        --version 0.1.0 \
        --source-revision 0123456789abcdef0123456789abcdef01234567 \
        --source-date-epoch 123 \
        --subject "$archive_fixture/runtime.tar.gz" \
        --subject "$archive_fixture/sources.tar.gz" \
        --material "file:Cargo.lock=$(sha256 "$packaging_dir/../Cargo.lock")" \
        --material "file:rust-toolchain.toml=$(sha256 "$packaging_dir/../rust-toolchain.toml")" \
        --tool "cargo=cargo 1.90.0" \
        --tool "rustc=rustc 1.90.0" \
        --evidence "SBOM.spdx.json=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
        --material "https://example.invalid/libkrun.tar.gz=$LIBKRUN_SOURCE_SHA256"
done
cmp "$archive_fixture/provenance-one.json" "$archive_fixture/provenance-two.json" \
    || fail "release provenance is not deterministic"
python3 - "$archive_fixture/provenance-one.json" \
    "$archive_fixture/runtime.tar.gz" "$archive_fixture/sources.tar.gz" <<'PY'
import hashlib, json, pathlib, sys
statement = json.load(open(sys.argv[1], encoding="utf-8"))
assert statement["_type"] == "https://in-toto.io/Statement/v1"
assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
subjects = {item["name"]: item["digest"]["sha256"] for item in statement["subject"]}
for name in sys.argv[2:]:
    path = pathlib.Path(name)
    assert subjects[path.name] == hashlib.sha256(path.read_bytes()).hexdigest()
materials = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
assert any(item["uri"] == "file:Cargo.lock" for item in materials)
assert any(item["uri"] == "file:rust-toolchain.toml" for item in materials)
assert any(item["digest"].get("gitCommit") for item in materials)
definition = statement["predicate"]["buildDefinition"]
assert definition["externalParameters"]["sourceDateEpoch"] == 123
assert definition["internalParameters"]["toolchain"] == {
    "cargo": "cargo 1.90.0",
    "rustc": "rustc 1.90.0",
}
assert definition["internalParameters"]["evidenceDigests"] == {
    "SBOM.spdx.json": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
}
PY

if [[ "$(uname -s)" == Darwin ]]; then
    if CDM_CODESIGN_IDENTITY=- "$packaging_dir/package.sh" release \
        >"$archive_fixture/release.out" 2>&1; then
        fail "production release accepted ad-hoc macOS signing"
    fi
    grep -q 'requires a non-ad-hoc CDM_CODESIGN_IDENTITY' "$archive_fixture/release.out" \
        || fail "macOS release did not explain its signing requirement"
fi

assert_file_content() {
    local path=$1 expected=$2
    [[ -f "$path" ]] || fail "missing file: $path"
    [[ "$(cat "$path")" == "$expected" ]] \
        || fail "unexpected content in $path"
}

make_fixture_package() {
    local package=$1 binary=$2 common=$3
    [[ ! -e "$package" ]] || fail "fixture package unexpectedly exists: $package"
    mkdir -p "$package/bin" "$package/lib/cdm"
    printf '%s' "$binary" > "$package/bin/cdm"
    printf '%s' "$common" > "$package/lib/cdm/libcommon"
    printf 'old-library' > "$package/lib/cdm/libstale"
    chmod 755 "$package/bin/cdm" "$package/lib/cdm/"*
    cp "$packaging_dir/install.sh" "$package/install.sh"
}

test_installer_lifecycle() (
    local root package prefix manifest fake_bin tmp_root
    root=$(mktemp -d "${TMPDIR:-/tmp}/cdm-packaging-test.XXXXXX")
    root=$(CDPATH= cd -- "$root" && pwd -P)
    tmp_root=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
    case "$(CDPATH= cd -- "$root" && pwd -P)" in
        "$packaging_dir"|"$packaging_dir"/*) fail "installer fixture resolved inside the repository" ;;
    esac
    cleanup_installer_fixture() {
        case "$root" in
            "$tmp_root"/cdm-packaging-test.*) command -p rm -rf -- "$root" ;;
            *) fail "refusing unsafe installer-fixture cleanup: $root" ;;
        esac
    }
    trap cleanup_installer_fixture EXIT
    package="$root/package"
    prefix="$root/prefix with spaces"
    manifest="$prefix/lib/cdm/install-manifest.sha256"

    make_fixture_package "$package" version-one common-one
    "$package/install.sh" install "$prefix" >/dev/null
    assert_file_content "$prefix/bin/cdm" version-one
    assert_file_content "$prefix/lib/cdm/libcommon" common-one
    [[ -f "$manifest" ]] || fail "installer did not write its ownership manifest"
    "$package/install.sh" verify "$prefix" >/dev/null

    printf 'unrelated' > "$prefix/lib/cdm/user-owned"
    "$package/install.sh" install "$prefix" >/dev/null
    assert_file_content "$prefix/lib/cdm/user-owned" unrelated

    command -p rm "$package/lib/cdm/libstale"
    printf 'version-two' > "$package/bin/cdm"
    printf 'common-two' > "$package/lib/cdm/libcommon"
    printf 'new-library' > "$package/lib/cdm/libnew"
    chmod 755 "$package/bin/cdm" "$package/lib/cdm/"*
    "$package/install.sh" install "$prefix" >/dev/null
    assert_file_content "$prefix/bin/cdm" version-two
    assert_file_content "$prefix/lib/cdm/libcommon" common-two
    assert_file_content "$prefix/lib/cdm/libnew" new-library
    [[ ! -e "$prefix/lib/cdm/libstale" ]] || fail "upgrade retained a stale owned library"
    assert_file_content "$prefix/lib/cdm/user-owned" unrelated
    "$package/install.sh" verify "$prefix" >/dev/null

    # A failed promotion after libraries changed must restore the previous install.
    fake_bin="$root/fake-bin"
    mkdir -p "$fake_bin"
    printf 'version-three' > "$package/bin/cdm"
    printf 'common-three' > "$package/lib/cdm/libcommon"
    if CDM_TEST_FAIL_DEST="$prefix/bin/cdm" \
        "$package/install.sh" install "$prefix" >/dev/null 2>&1; then
        fail "installer succeeded after an injected promotion failure"
    fi
    assert_file_content "$prefix/bin/cdm" version-two
    assert_file_content "$prefix/lib/cdm/libcommon" common-two
    "$package/install.sh" verify "$prefix" >/dev/null

    printf 'tampered' > "$prefix/bin/cdm"
    if "$package/install.sh" verify "$prefix" >/dev/null 2>&1; then
        fail "verify accepted a modified installed file"
    fi
    if "$package/install.sh" uninstall "$prefix" >/dev/null 2>&1; then
        fail "uninstall removed a modified owned file"
    fi
    assert_file_content "$prefix/bin/cdm" tampered

    # Reinstall repairs owned paths, then uninstall removes only manifest-owned files.
    "$package/install.sh" install "$prefix" >/dev/null
    "$package/install.sh" uninstall "$prefix" >/dev/null
    [[ ! -e "$prefix/bin/cdm" ]] || fail "uninstall retained the CDM binary"
    [[ ! -e "$prefix/lib/cdm/libcommon" ]] || fail "uninstall retained an owned library"
    [[ ! -e "$manifest" ]] || fail "uninstall retained the ownership manifest"
    assert_file_content "$prefix/lib/cdm/user-owned" unrelated

    # The historical one-argument spelling remains the default install command.
    "$package/install.sh" "$prefix" >/dev/null
    "$package/install.sh" verify "$prefix" >/dev/null

    HOME="$root/default-home" "$package/install.sh" >/dev/null
    assert_file_content "$root/default-home/.local/bin/cdm" version-three
    HOME="$root/default-home" "$package/install.sh" verify >/dev/null
    HOME="$root/default-home" "$package/install.sh" uninstall >/dev/null

    local collision="$root/collision"
    mkdir -p "$collision/bin"
    printf 'not-cdm' > "$collision/bin/cdm"
    if "$package/install.sh" install "$collision" >/dev/null 2>&1; then
        fail "installer overwrote a path it did not own"
    fi
    assert_file_content "$collision/bin/cdm" not-cdm

    local hostile="$root/hostile" victim_hash
    mkdir -p "$hostile/lib/cdm"
    printf 'do-not-delete' > "$root/victim"
    victim_hash=$(sha256 "$root/victim")
    printf '%s\t%s\n' "$victim_hash" '../../victim' \
        > "$hostile/lib/cdm/install-manifest.sha256"
    if "$package/install.sh" uninstall "$hostile" >/dev/null 2>&1; then
        fail "uninstall accepted a traversal path in its ownership manifest"
    fi
    assert_file_content "$root/victim" do-not-delete

    # A prefix is a security boundary. Every existing ancestor and managed
    # directory must be a real, owner-safe directory; an attacker must not be
    # able to redirect promotion through a symlink or writable parent.
    local outside="$root/outside" symlink_parent="$root/symlink-parent"
    mkdir -p "$outside" "$symlink_parent"
    ln -s "$outside" "$symlink_parent/redirect"
    if "$package/install.sh" install "$symlink_parent/redirect/prefix" >/dev/null 2>&1; then
        fail "installer accepted a symlink prefix ancestor"
    fi
    [[ ! -e "$outside/prefix/bin/cdm" ]] \
        || fail "installer promoted through a symlink prefix ancestor"

    printf 'not-a-directory' > "$root/file-parent"
    if "$package/install.sh" install "$root/file-parent/prefix" >/dev/null 2>&1; then
        fail "installer accepted a non-directory prefix ancestor"
    fi

    mkdir -p "$root/writable-parent"
    chmod 777 "$root/writable-parent"
    if "$package/install.sh" install "$root/writable-parent/prefix" >/dev/null 2>&1; then
        fail "installer accepted a cross-user-writable prefix ancestor"
    fi
    chmod 700 "$root/writable-parent"

    local redirected="$root/redirected-managed" managed="$root/managed-prefix"
    mkdir -p "$redirected" "$managed"
    ln -s "$redirected" "$managed/lib"
    if "$package/install.sh" install "$managed" >/dev/null 2>&1; then
        fail "installer accepted a symlink managed directory"
    fi
    [[ ! -e "$redirected/cdm/libcommon" ]] \
        || fail "installer promoted through a symlink managed directory"

    # Treat mktemp output as untrusted: an empty or redirected result must
    # never become a cleanup/promotion operand.
    if CDM_TEST_MKTEMP_RESULT='' \
        "$package/install.sh" install "$root/empty-mktemp-prefix" >/dev/null 2>&1; then
        fail "installer accepted an empty mktemp result"
    fi
    [[ ! -e "$root/empty-mktemp-prefix/bin/cdm" ]] \
        || fail "installer promoted after an empty mktemp result"
    if CDM_TEST_MKTEMP_RESULT="$outside" \
        "$package/install.sh" install "$root/redirected-mktemp-prefix" >/dev/null 2>&1; then
        fail "installer accepted an out-of-prefix mktemp result"
    fi
    [[ ! -e "$outside/bin/cdm" ]] \
        || fail "installer promoted through redirected mktemp output"

    # Installer commands must never resolve through the caller's PATH, even
    # when an install is run with elevated privileges.
    local marker="$root/path-shim-executed" tool
    for tool in dirname id stat shasum sha256sum awk mktemp mkdir cp install mv; do
        cat > "$fake_bin/$tool" <<EOF
#!/bin/sh
printf '%s\n' '$tool' >> '$marker'
exit 91
EOF
        chmod 755 "$fake_bin/$tool"
    done
    PATH="$fake_bin:$PATH" "$package/install.sh" verify "$prefix" >/dev/null
    PATH="$fake_bin:$PATH" "$package/install.sh" install "$prefix" >/dev/null
    PATH="$fake_bin:$PATH" "$package/install.sh" uninstall "$prefix" >/dev/null
    [[ ! -e "$marker" ]] || fail "installer executed a caller-controlled PATH shim"
    "$package/install.sh" install "$prefix" >/dev/null

    local hostile_upgrade="$root/hostile-upgrade"
    "$package/install.sh" install "$hostile_upgrade" >/dev/null
    mv "$hostile_upgrade/lib" "$hostile_upgrade/lib.saved"
    ln -s "$outside" "$hostile_upgrade/lib"
    if "$package/install.sh" install "$hostile_upgrade" >/dev/null 2>&1; then
        fail "upgrade accepted a redirected managed-directory parent"
    fi
    [[ ! -e "$outside/cdm/libcommon" ]] \
        || fail "upgrade promoted outside its prefix"
    command -p rm -f -- "$hostile_upgrade/lib"
    mv "$hostile_upgrade/lib.saved" "$hostile_upgrade/lib"
    "$package/install.sh" verify "$hostile_upgrade" >/dev/null
    "$package/install.sh" uninstall "$hostile_upgrade" >/dev/null

    # Files with multiple hard links are not exclusively owned by the prefix:
    # changing or removing them could mutate content reachable elsewhere.
    local linked="$root/hardlink-prefix"
    "$package/install.sh" install "$linked" >/dev/null
    ln "$linked/bin/cdm" "$root/cdm-hardlink"
    if "$package/install.sh" verify "$linked" >/dev/null 2>&1; then
        fail "verify accepted a hard-linked owned file"
    fi
    if "$package/install.sh" install "$linked" >/dev/null 2>&1; then
        fail "upgrade accepted a hard-linked owned file"
    fi
    assert_file_content "$root/cdm-hardlink" version-three
    command -p rm -f -- "$root/cdm-hardlink"
    "$package/install.sh" verify "$linked" >/dev/null

    ln "$linked/lib/cdm/install-manifest.sha256" "$root/manifest-hardlink"
    if "$package/install.sh" verify "$linked" >/dev/null 2>&1; then
        fail "verify accepted a hard-linked ownership manifest"
    fi
    command -p rm -f -- "$root/manifest-hardlink"
    "$package/install.sh" uninstall "$linked" >/dev/null

)

test_installer_lifecycle

echo "packaging metadata: ok"
