"""Times the interactive session's start-up (bench scenario `repl-startup`).

Usage: python3 -I bench/repl_pty.py <snow> sql -x --no-prompt-exit-repl

Runs the command on a pseudo-terminal, waits for its first prompt (bracketed paste switched
on, which both prompt_toolkit and rustyline do when they start reading), types `quit` and
Enter, and waits for the process to end. It fails if that takes over 60 s or the exit code is
not 0. Nothing it reads is printed.
"""

import os
import pty
import select
import sys
import time

READING = b"\x1b[?2004h"


def main() -> int:
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(sys.argv[1], sys.argv[1:])
    deadline = time.monotonic() + 60
    seen = b""
    sent = False
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            seen = (seen + chunk)[-4096:]
        if not sent and READING in seen:
            # Let the editor finish drawing the prompt before typing.
            time.sleep(0.05)
            os.write(fd, b"quit\r")
            sent = True
    _, status = os.waitpid(pid, 0)
    return 0 if sent and os.waitstatus_to_exitcode(status) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
