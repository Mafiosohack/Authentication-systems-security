"""launch.py -- start a set of (name, path, port) servers as subprocesses,
wait until each answers, yield, then tear them down. Used by test harnesses.

Cross-platform: works on Windows, Linux and macOS. Each server is a single
Python process (Flask, threaded), so a plain terminate()/wait() is enough --
no POSIX process groups required."""
import subprocess, sys, time, socket, contextlib


def _up(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        with contextlib.closing(socket.socket()) as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False


@contextlib.contextmanager
def servers(specs):
    procs = []
    try:
        for name, path, port in specs:
            p = subprocess.Popen([sys.executable, path],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True)
            procs.append((name, p, port))
        for name, p, port in procs:
            if not _up(port):
                out = ""
                with contextlib.suppress(Exception):
                    p.terminate()
                    out = p.stdout.read()
                raise RuntimeError(f"{name} failed to start on :{port}\n{out}")
        time.sleep(0.4)
        yield
    finally:
        for name, p, port in procs:
            with contextlib.suppress(Exception):
                p.terminate()
        for name, p, port in procs:
            with contextlib.suppress(Exception):
                p.wait(timeout=5)
        time.sleep(0.5)
