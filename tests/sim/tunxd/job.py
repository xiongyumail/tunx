#!/usr/bin/env python3
"""Own one remote scenario process and acknowledge cancellation after it exits."""
import argparse
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "stop"))
    parser.add_argument("--jobdir", required=True)
    words = list(sys.argv[1:] if argv is None else argv)
    split = words.index("--") if "--" in words else len(words)
    args = parser.parse_args(words[:split])
    command = words[split + 1:]
    directory = Path(args.jobdir)
    directory.mkdir(parents=True, exist_ok=True)
    stopped = directory / "stop"
    if args.action == "stop":
        stopped.touch()  # Also prevents a queued SSH command from starting later.
    with (directory / "owner.lock").open("a") as lock:
        deadline = time.monotonic() + 20
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if args.action == "run" or time.monotonic() >= deadline:
                    raise RuntimeError("remote scenario did not acknowledge cancellation")
                time.sleep(0.1)
        if args.action == "stop":
            return 0  # The supervisor has waited for its child before unlocking.
        if stopped.exists():
            return 143
        if not command:
            parser.error("run requires a command after --")
        status = 0

        def cancel(signum, frame):
            nonlocal status
            status = 128 + signum
            stopped.touch()

        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, cancel)
        process = subprocess.Popen(command, start_new_session=True)
        while process.poll() is None and not stopped.exists():
            time.sleep(0.1)
        if stopped.exists() and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        result = process.wait()
        return status or (143 if stopped.exists() else 128 - result if result < 0 else result)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"job: {error}", file=sys.stderr)
        sys.exit(1)
