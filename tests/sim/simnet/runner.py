"""Execute actions for real (root, in the test VM) or print them (dry run)."""
import os
import shlex
import signal
import subprocess
import sys
import time

from . import SimError
from .actions import Cmd, DelNs, KillNs, Mkdir, Remove, Spawn, Write


class Runner:
    def __init__(self, dry=False, out=None, verbose=False):
        self.dry = dry
        self.out = out or sys.stdout
        self.verbose = verbose

    def say(self, text):
        print(text, file=self.out, flush=True)

    # Namespace queries (empty in dry runs).
    def list_ns(self):
        if self.dry:
            return []
        r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
        return [line.split()[0] for line in r.stdout.splitlines() if line.strip()]

    def ns_pids(self, ns):
        r = subprocess.run(["ip", "netns", "pids", ns], capture_output=True, text=True)
        return [int(p) for p in r.stdout.split() if p.isdigit()]

    def do_all(self, actions):
        for a in actions:
            self.do(a)

    def do(self, a):
        if self.dry:
            self.say(a.shell())
            return
        if self.verbose:
            self.say("+ " + a.shell().splitlines()[0])
        if isinstance(a, Cmd):
            r = subprocess.run(a.argv, capture_output=True, text=True)
            if r.returncode and a.check:
                raise SimError(f"command failed (exit {r.returncode}): {shlex.join(a.argv)}\n"
                               f"{(r.stderr or r.stdout).strip()}")
        elif isinstance(a, Mkdir):
            os.makedirs(a.path, exist_ok=True)
        elif isinstance(a, Write):
            with open(a.path, "wb") as f:
                f.write(a.content)
            os.chmod(a.path, a.mode)
        elif isinstance(a, Spawn):
            self.spawn(a)
        elif isinstance(a, KillNs):
            self.kill_ns(a.ns)
        elif isinstance(a, DelNs):
            if a.ns in self.list_ns():
                r = subprocess.run(["ip", "netns", "del", a.ns], capture_output=True, text=True)
                if r.returncode:
                    self.say(f"warning: ip netns del {a.ns}: {r.stderr.strip()}")
        elif isinstance(a, Remove):
            try:
                os.remove(a.path)
            except FileNotFoundError:
                pass
        else:
            raise TypeError(a)

    def spawn(self, a):
        env = dict(os.environ, **a.env)
        with open(a.log, "ab") as log:
            log.write(f"=== {time.strftime('%F %T')} start: {a.cmd}\n".encode())
            log.flush()
            p = subprocess.Popen(["ip", "netns", "exec", a.ns, "sh", "-c", a.cmd], cwd=a.cwd, env=env,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        if a.pidfile:
            with open(a.pidfile, "w") as f:
                f.write(f"{p.pid}\n")
        return p

    def kill_ns(self, ns):
        if ns not in self.list_ns():
            return
        for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 1.0)):
            pids = self.ns_pids(ns)
            if not pids:
                return
            for pid in pids:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline and self.ns_pids(ns):
                time.sleep(0.1)
        left = self.ns_pids(ns)
        if left:
            self.say(f"warning: processes still alive in {ns}: {left}")

    def capture(self, ns, cmd, timeout=30):
        """Run a shell command in a namespace. Returns (rc, output, timed_out, seconds)."""
        argv = ["ip", "netns", "exec", ns, "sh", "-c", cmd]
        if self.dry:
            self.say(f"  $ {shlex.join(argv)}")
            return 0, "", False, 0.0
        t0 = time.monotonic()
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
        try:
            out, _ = p.communicate(timeout=timeout)
            return p.returncode, out.decode(errors="replace"), False, time.monotonic() - t0
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, _ = p.communicate()
            return -1, out.decode(errors="replace"), True, time.monotonic() - t0
