#!/usr/bin/env python3
"""Launch the exact CDM artifact with a non-UTF-8 Unix argument."""
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: argv_bytes_probe.py CDM MODE")

cdm = os.fsencode(sys.argv[1])
mode = sys.argv[2]
if mode == "native":
    mode_args: list[bytes] = []
elif mode == "vm":
    mode_args = [b"--vm"]
elif mode.startswith("vmi/"):
    mode_args = [b"--vmi", os.fsencode(mode.removeprefix("vmi/"))]
else:
    raise SystemExit(f"unsupported mode: {mode}")

opaque = bytes([0xFF]) + b" space\n*?[]"
probe = b'printf "%s" "$1" | od -An -tx1 | tr -d " \\n"'
command = [
    cdm,
    *mode_args,
    b"--no-proxy",
    b"--",
    b"/bin/sh",
    b"-c",
    probe,
    b"argv-probe",
    opaque,
]
result = subprocess.run(
    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
)
if result.returncode != 0:
    sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)
expected = opaque.hex().encode("ascii")
if result.stdout != expected:
    print(f"expected {expected!r}, got {result.stdout!r}", file=sys.stderr)
    raise SystemExit(1)
