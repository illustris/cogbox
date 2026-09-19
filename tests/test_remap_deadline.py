"""Exercise the actual LD_PRELOAD connect wrapper against a stalled proxy.

Usage: NETFILTER_TEST_LIB=/path/to/libnetfilter.so python3 tests/test_remap_deadline.py
The proxy is local and no external network connection is attempted.
"""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


def client():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    libc.connect.restype = ctypes.c_int
    # sockaddr_in: native family, network-order port/address, eight pad bytes.
    address = ctypes.create_string_buffer(
        struct.pack("=H", socket.AF_INET)
        + struct.pack("!H", 443)
        + socket.inet_aton("203.0.113.7")
        + bytes(8)
    )
    observations = []
    for nonblocking in (True, False):
        with socket.socket() as sock:
            sock.setblocking(not nonblocking)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("@ll", 13, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("@ll", 17, 0))
            flags = fcntl.fcntl(sock, fcntl.F_GETFL)
            options = [sock.getsockopt(socket.SOL_SOCKET, opt, 16)
                       for opt in (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO)]
            start = time.monotonic()
            rc = libc.connect(sock.fileno(), address, 16)
            error = ctypes.get_errno()
            elapsed = time.monotonic() - start
            assert fcntl.fcntl(sock, fcntl.F_GETFL) == flags
            assert options == [sock.getsockopt(socket.SOL_SOCKET, opt, 16)
                               for opt in (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO)]
            if rc == 0:
                # The handshake deadline must not persist into application I/O.
                sock.sendall(b"application-data")
            observations.append(dict(rc=rc, errno=error, elapsed=elapsed))
    print(json.dumps(observations))


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise AssertionError("unexpected EOF")
        data += chunk
    return data


class RemapDeadlineTest(unittest.TestCase):
    def test_stalled_proxy_times_out_then_next_connection_works(self):
        library = os.environ["NETFILTER_TEST_LIB"]
        self.assertTrue(Path(library).is_file())
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(15)
            port = listener.getsockname()[1]
            rules = Path(tmp) / "rules"
            rules.write_text(f"remap tcp 203.0.113.7/32:443 -> tcp 127.0.0.1:{port}\n")
            errors = []
            greeting_seen = threading.Event()
            stalled_closed = threading.Event()

            def proxy():
                try:
                    # Keep the first socket open and silent while accepting the
                    # second. This reproduces a worker stuck before its timeout.
                    stalled, _ = listener.accept()
                    with stalled:
                        stalled.settimeout(10)
                        self.assertEqual(read_exact(stalled, 3), b"\x05\x01\x00")
                        greeting_seen.set()
                        # The client closes this socket the moment it has
                        # recorded the timed-out connect. That EOF is the
                        # signal to stop the signal storm, so the healthy
                        # connection below is dialled in quiet conditions.
                        self.assertEqual(stalled.recv(1), b"")
                        stalled_closed.set()
                        healthy, _ = listener.accept()
                        with healthy:
                            healthy.settimeout(3)
                            self.assertEqual(read_exact(healthy, 3), b"\x05\x01\x00")
                            healthy.sendall(b"\x05\x00")
                            request = read_exact(healthy, 10)
                            self.assertEqual(request, b"\x05\x01\x00\x01" + socket.inet_aton("203.0.113.7") + struct.pack("!H", 443))
                            healthy.sendall(b"\x05\x00\x00\x01" + bytes(6))
                            self.assertEqual(read_exact(healthy, 16), b"application-data")
                except BaseException as exc:
                    errors.append(exc)

            server = threading.Thread(target=proxy, daemon=True)
            server.start()
            env = dict(os.environ, LD_PRELOAD=library, NETFILTER_RULES=str(rules))
            with subprocess.Popen([sys.executable, __file__, "--client"],
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True) as process:
                stop_signals = threading.Event()

                def interrupt_reads():
                    if not greeting_seen.wait(5):
                        return
                    # The shim's existing SIGUSR1 handler interrupts read().
                    # A fresh timeout after each EINTR would never complete.
                    # The storm is scoped to the stalled observation: it stops
                    # as soon as the proxy sees that connection close.
                    while not stalled_closed.wait(0.02):
                        if stop_signals.is_set():
                            return
                        try:
                            os.kill(process.pid, signal.SIGUSR1)
                        except ProcessLookupError:
                            return

                interrupter = threading.Thread(target=interrupt_reads, daemon=True)
                interrupter.start()
                try:
                    stdout, stderr = process.communicate(timeout=15)
                finally:
                    stop_signals.set()
                    interrupter.join(timeout=6)
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            server.join(timeout=16)
            self.assertFalse(server.is_alive(), "proxy test thread did not finish")
            self.assertEqual(result.returncode, 0, result.stderr)
            if errors:
                raise errors[0]
            stalled, healthy = json.loads(result.stdout)
            self.assertEqual((stalled["rc"], stalled["errno"]), (-1, errno.ETIMEDOUT))
            self.assertGreaterEqual(stalled["elapsed"], 4.5)
            self.assertLess(stalled["elapsed"], 8)
            self.assertEqual(healthy["rc"], 0)
            self.assertLess(healthy["elapsed"], 2)


if __name__ == "__main__":
    if sys.argv[1:] == ["--client"]:
        client()
    else:
        unittest.main()
