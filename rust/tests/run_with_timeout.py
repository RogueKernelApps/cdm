#!/usr/bin/env python3
"""Run a command with a timeout and terminate its entire process group."""

from __future__ import annotations

import os
import signal
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: run_with_timeout.py SECONDS COMMAND [ARG ...]", file=sys.stderr)
        return 2

    try:
        timeout = float(sys.argv[1])
    except ValueError:
        print(f"invalid timeout: {sys.argv[1]}", file=sys.stderr)
        return 2
    if timeout <= 0:
        print("timeout must be positive", file=sys.stderr)
        return 2

    process = subprocess.Popen(sys.argv[2:], start_new_session=True)
    try:
        status = process.wait(timeout=timeout)
        return status if status >= 0 else 128 - status
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
