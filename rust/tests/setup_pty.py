#!/usr/bin/env python3
"""Run the exact CDM artifact's interactive setup command through a PTY."""

import errno
import os
import select
import sys
import time


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: setup_pty.py /absolute/path/to/cdm keys-hex")
    cdm = sys.argv[1]
    keys = bytes.fromhex(sys.argv[2])
    pid, master = os.forkpty()
    if pid == 0:
        environment = os.environ.copy()
        environment.setdefault("TERM", "xterm-256color")
        os.execve(cdm, [cdm, "setup"], environment)

    output = bytearray()
    sent = False
    deadline = time.monotonic() + 10
    status = None
    while time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output.extend(chunk)
            if not sent and b"Enable detected CDM profiles" in output:
                os.write(master, keys)
                sent = True
        waited, value = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            status = value
            break
    if status is None:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == 0:
            os.kill(pid, 9)
            _, status = os.waitpid(pid, 0)
            output.extend(b"\nsetup PTY timed out\n")
    os.close(master)
    sys.stdout.buffer.write(output)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
