#!/usr/bin/env bash
set -euo pipefail

packaging_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=versions.env
source "$packaging_dir/versions.env"

python3 - "$LIBKRUN_VERSION" "$LIBKRUNFW_VERSION" "$LINUX_VERSION" "$ALPINE_VERSION" <<'PY'
import json
import re
import sys
from urllib.request import Request, urlopen


def fetch(url: str):
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "cdm-release-check"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def version(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"v?(\d+(?:\.\d+)+)", value)
    if not match:
        raise ValueError(value)
    return tuple(int(part) for part in match.group(1).split("."))


def latest_release(repository: str, major: int | None = None) -> str:
    releases = fetch(f"https://api.github.com/repos/{repository}/releases?per_page=100")
    candidates = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        try:
            parsed = version(release["tag_name"])
        except (KeyError, ValueError):
            continue
        if major is None or parsed[0] == major:
            candidates.append((parsed, release["tag_name"].lstrip("v")))
    if not candidates:
        raise RuntimeError(f"no stable releases found for {repository}")
    return max(candidates)[1]


current_krun, current_fw, current_kernel, current_alpine = sys.argv[1:]
latest = {
    "libkrun stable 1.x": latest_release("containers/libkrun", major=1),
    "libkrunfw": latest_release("containers/libkrunfw"),
}

kernel_line = ".".join(current_kernel.split(".")[:2]) + "."
kernel_releases = fetch("https://www.kernel.org/releases.json")["releases"]
kernel_candidates = [item["version"] for item in kernel_releases if item["version"].startswith(kernel_line)]
if not kernel_candidates:
    raise RuntimeError(f"no kernel.org release found for {kernel_line}x")
latest["Linux LTS line"] = max(kernel_candidates, key=version)

alpine_line = ".".join(current_alpine.split(".")[:2])
alpine_index = urlopen(
    f"https://dl-cdn.alpinelinux.org/alpine/v{alpine_line}/releases/aarch64/",
    timeout=30,
).read().decode()
alpine_candidates = re.findall(
    rf"alpine-minirootfs-({re.escape(alpine_line)}\.\d+)-aarch64\.tar\.gz<",
    alpine_index,
)
if not alpine_candidates:
    raise RuntimeError(f"no Alpine release found for {alpine_line}.x")
latest["Alpine rootfs line"] = max(alpine_candidates, key=version)

current = {
    "libkrun stable 1.x": current_krun,
    "libkrunfw": current_fw,
    "Linux LTS line": current_kernel,
    "Alpine rootfs line": current_alpine,
}
stale = []
for name, selected in current.items():
    upstream = latest[name]
    qualifier = " (corresponding firmware source; informational)" if name == "Linux LTS line" else ""
    print(f"{name}: selected {selected}; upstream {upstream}{qualifier}")
    if name == "Linux LTS line":
        continue
    if version(selected) < version(upstream):
        stale.append(f"{name} {selected} -> {upstream}")

if stale:
    print("outdated pinned runtime inputs: " + ", ".join(stale), file=sys.stderr)
    raise SystemExit(1)
PY
