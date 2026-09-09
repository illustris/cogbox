"""Native smoke checks: real dyld/socket filtering, stream framing and lifecycle.

Run with COGBOX, COGBOX_PLATFORM, COGBOX_SLIRP, COGBOX_NETFILTER,
COGBOX_NET_PROBE pointing at built artifacts. All state and ports are temporary.
"""
import contextlib
import concurrent.futures
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest


class DarwinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cbx-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def spawn(self, argv, **kwargs):
        p = subprocess.Popen(argv, **kwargs)
        def cleanup():
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            for stream in (p.stdin, p.stdout, p.stderr):
                if stream is not None:
                    stream.close()
        self.addCleanup(cleanup)
        return p

    def test_filter_and_reload(self):
        with contextlib.ExitStack() as stack:
            route = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            # Route lookup only: connect on UDP sends no packet.
            route.connect(("192.0.2.1", 9))
            host = route.getsockname()[0]
            tcp = stack.enter_context(socket.socket())
            tcp.bind((host, 0)); tcp.listen()
            port = tcp.getsockname()[1]
            udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp.bind((host, port))
            rules = self.root / "rules"
            rules.write_text("allow 0.0.0.0/0\n")
            env = dict(os.environ, NETFILTER_RULES=str(rules),
                       DYLD_INSERT_LIBRARIES=os.environ["COGBOX_NETFILTER"])
            p = self.spawn([os.environ["COGBOX_NET_PROBE"], host, str(port)], env=env,
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            def probe(mode):
                p.stdin.write(mode + "\n"); p.stdin.flush()
                self.assertTrue(select.select([p.stdout], [], [], 5)[0], "probe timed out")
                return p.stdout.readline().strip()
            for mode in "tuc":
                self.assertEqual(probe(mode), "allowed", mode)
            # Truncate in place: the shim intentionally holds this inode.
            rules.write_text("deny 0.0.0.0/0\n")
            p.send_signal(signal.SIGUSR1)
            time.sleep(0.05)
            for mode in "tuc":
                self.assertEqual(probe(mode), "denied", mode)
            rules.write_text("allow 0.0.0.0/0\n")
            p.send_signal(signal.SIGUSR1)
            time.sleep(0.05)
            self.assertEqual(probe("u"), "allowed")
            p.stdin.close()
            self.assertEqual(p.wait(timeout=5), 0)

    @staticmethod
    def arp_request(mac):
        # Ask the virtual gateway for its MAC.
        return (b"\xff" * 6 + mac + b"\x08\x06" +
                struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac +
                socket.inet_aton("10.0.2.15") + b"\0" * 6 + socket.inet_aton("10.0.2.2"))

    def read_frame(self, link):
        def exact(n):
            data = b""
            while len(data) < n:
                part = link.recv(n - len(data))
                self.assertTrue(part)
                data += part
            return data
        return exact(struct.unpack("!I", exact(4))[0])

    def wait_for_socket(self, path, p):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            self.assertIsNone(p.poll())
            time.sleep(0.01)

    def test_slirp_framing(self):
        self.check_slirp_framing(filtered=False)

    def test_filtered_slirp_framing(self):
        self.check_slirp_framing(filtered=True)

    def check_slirp_framing(self, filtered):
        path = self.root / "net.sock"
        env = dict(os.environ)
        args = [os.environ["COGBOX_SLIRP"], "--socket", str(path), "-4"]
        if filtered:
            rules = self.root / "rules"
            rules.write_text("deny 0.0.0.0/0\n")
            env.update(NETFILTER_RULES=str(rules),
                       DYLD_INSERT_LIBRARIES=os.environ["COGBOX_NETFILTER"])
            args.append("--filtered")
        p = self.spawn(args, env=env)
        self.wait_for_socket(path, p)
        with socket.socket(socket.AF_UNIX) as link:
            link.settimeout(5); link.connect(str(path))
            mac = bytes.fromhex("525400123456")
            arp = self.arp_request(mac)
            frame = struct.pack("!I", len(arp)) + arp
            # Split across stream reads.
            for chunk in (frame[:2], frame[2:9], frame[9:]):
                link.sendall(chunk)
            reply = self.read_frame(link)
            self.assertEqual(reply[:6], mac)
            self.assertEqual(reply[12:14], b"\x08\x06")
            self.assertEqual(reply[20:22], b"\x00\x02")
            # An invalid length closes the stream instead of allocating it.
            link.sendall(struct.pack("!I", 0xFFFFFFFF))
            self.assertEqual(link.recv(1), b"")
        self.assertEqual(p.wait(timeout=5), 0)

    def test_slirp_survives_stalled_reader(self):
        # QEMU stops reading the stream while the guest cannot receive (a
        # paused VM). Replies must wait for it, not close the link: the helper
        # used to time out after 1s and exit, leaving the guest without network.
        path = self.root / "net.sock"
        p = self.spawn([os.environ["COGBOX_SLIRP"], "--socket", str(path), "-4"])
        self.wait_for_socket(path, p)
        with socket.socket(socket.AF_UNIX) as link:
            link.settimeout(5); link.connect(str(path))
            mac = bytes.fromhex("525400123456")
            arp = self.arp_request(mac)
            frame = struct.pack("!I", len(arp)) + arp
            # Replies well beyond the ~8 KiB a Unix stream buffers per direction,
            # while the unread requests still fit in the other direction.
            requests = 250
            for _ in range(requests):
                link.sendall(frame)
            time.sleep(1.5)
            self.assertIsNone(p.poll(), "helper gave up on a stalled reader")
            for _ in range(requests):
                self.assertEqual(self.read_frame(link)[:6], mac)
            # The link still works once drained.
            link.sendall(frame)
            self.assertEqual(self.read_frame(link)[:6], mac)
        self.assertEqual(p.wait(timeout=5), 0)

    def test_slirp_termination_during_fragmented_reply(self):
        # A large UDP reply makes libslirp send several fragments in one
        # callback. After interrupting a blocked fragment, shutdown must also
        # cancel the remaining fragments while QEMU keeps the stream open.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(("192.0.2.1", 9))  # Route lookup; sends no packet.
            host = route.getsockname()[0]
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                server.bind((host, 0)); server.settimeout(5)
                path = self.root / (sig.name + ".sock")
                p = self.spawn([os.environ["COGBOX_SLIRP"], "--socket", str(path), "-4"],
                               stderr=subprocess.PIPE)
                self.wait_for_socket(path, p)
                with socket.socket(socket.AF_UNIX) as link:
                    link.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                    link.settimeout(5); link.connect(str(path))
                    def send_frame(frame):
                        link.sendall(struct.pack("!I", len(frame)) + frame)
                    mac = bytes.fromhex("525400123456")
                    send_frame(self.arp_request(mac))
                    gateway = self.read_frame(link)[6:12]
                    payload = b"fragmented-reply"
                    # IPv4 permits a zero UDP checksum; compute the IP checksum.
                    udp = struct.pack("!HHHH", 5555, server.getsockname()[1],
                                      8 + len(payload), 0) + payload
                    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0,
                                         64, 17, 0, socket.inet_aton("10.0.2.15"),
                                         socket.inet_aton(host))
                    checksum = sum(struct.unpack("!10H", header))
                    while checksum >> 16:
                        checksum = (checksum & 0xFFFF) + (checksum >> 16)
                    header = header[:10] + struct.pack("!H", (~checksum) & 0xFFFF) + header[12:]
                    send_frame(gateway + mac + b"\x08\x00" + header + udp)
                    request, peer = server.recvfrom(65535)
                    self.assertEqual(request, payload)
                    server.sendto(b"x" * 10000, peer)
                    self.assertTrue(select.select([link], [], [], 5)[0])
                    time.sleep(0.15)  # Let the unread fragments fill the stream.
                    self.assertIsNone(p.poll())
                    p.send_signal(sig)
                    self.assertEqual(p.wait(timeout=2), 0)
                    self.assertFalse(path.exists())

    def test_platform_process_and_lock(self):
        helper = os.environ["COGBOX_PLATFORM"]
        p = self.spawn(["sleep", "30"])
        info = subprocess.check_output([helper, "process", str(p.pid)], text=True).split()
        self.assertGreater(int(info[0]), 0)
        self.assertEqual(int(info[1]), os.getpid())
        self.assertEqual(info[2], "0")
        p.terminate(); p.wait(timeout=5)
        self.assertEqual(subprocess.run([helper, "process", str(p.pid)]).returncode, 3)
        import fcntl
        with (self.root / "lock").open("w") as owner, (self.root / "lock").open("r") as probe:
            fcntl.flock(owner, fcntl.LOCK_EX)
            argv = [helper, "flock", "-w", "0.01", str(probe.fileno())]
            self.assertEqual(subprocess.run(argv, pass_fds=(probe.fileno(),)).returncode, 1)
            fcntl.flock(owner, fcntl.LOCK_UN)
            self.assertEqual(subprocess.run(argv, pass_fds=(probe.fileno(),)).returncode, 0)

    def test_missing_filter_refuses_rules_mode(self):
        path = self.root / "net.sock"
        env = dict(os.environ)
        env.pop("DYLD_INSERT_LIBRARIES", None)
        p = subprocess.run([os.environ["COGBOX_SLIRP"], "--filtered", "--socket", str(path)],
                           env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, 70)
        self.assertFalse(path.exists())

    def test_cli_socket_clients(self):
        # Exercise the real TCP/Unix clients, which must not pass Darwin's
        # synthetic SOCK_CLOEXEC value directly to libc socket(). The SSH
        # readiness function is also used by start's default auto-attach path.
        import fcntl
        runtime = self.root / "run/cogbox"
        runtime.mkdir(parents=True)
        config = self.root / "config/cogbox/instances/default"
        config.mkdir(parents=True)
        (config / "config.json").write_text("{}")
        (runtime / "pid").write_text(str(os.getpid()))
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        ssh = bin_dir / "ssh"
        ssh.write_text("#!/bin/sh\nprintf 'ssh-exec-ok\\n'\n")
        ssh.chmod(0o755)
        # Bypass only the PATH wrapper so execvp finds the SSH fixture after
        # readiness. This is the same installed CLI executable the wrapper runs.
        cogbox = str(Path(os.environ["COGBOX"]).with_name(".cogbox-wrapped"))
        env = dict(os.environ, HOME=str(self.root), XDG_CONFIG_HOME=str(self.root / "config"),
                   XDG_DATA_HOME=str(self.root / "data"), XDG_RUNTIME_DIR=str(runtime.parent),
                   PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
        def cli(*args, devnull=False):
            stdin = {"stdin": subprocess.DEVNULL} if devnull else {"input": ""}
            return subprocess.run([cogbox, *args], env=env, text=True,
                                  capture_output=True, timeout=5, **stdin)
        def serve(listener, handler):
            listener.settimeout(3)
            listener.listen()
            def accept():
                with listener.accept()[0] as peer:
                    peer.settimeout(3)
                    handler(peer)
            return executor.submit(accept)
        with (runtime.parent / "cogbox.lock").open("w") as lock, \
                concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
                (runtime / "ssh-endpoint").write_text(f"{port} 127.0.0.1\n")
                server = serve(listener, lambda peer: peer.sendall(b"SSH-2.0-fixture\r\n"))
                result = cli("ssh", "--wait-for-ssh", "--wait-timeout", "1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "ssh-exec-ok\n")
                server.result(timeout=3)
            # A halted guest must override the still-held launcher lock. A
            # failed QMP socket used to fall back silently to "running".
            def qmp(peer):
                with peer.makefile("rwb", buffering=0) as stream:
                    stream.write(b'{"QMP":{}}\n')
                    self.assertEqual(json.loads(stream.readline())["execute"], "qmp_capabilities")
                    stream.write(b'{"return":{}}\n')
                    self.assertEqual(json.loads(stream.readline())["execute"], "query-status")
                    stream.write(b'{"return":{"status":"guest-panicked"}}\n')
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(runtime / "cogbox.socket"))
                server = serve(listener, qmp)
                result = cli("status")
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, "stopped\n")
                server.result(timeout=3)
            # Console and monitor share the same Unix socket attach function.
            for verb, name in (("console", "console.sock"), ("monitor", "monitor.sock")):
                with self.subTest(verb=verb), socket.socket(socket.AF_UNIX) as listener:
                    listener.bind(str(runtime / name))
                    server = serve(listener, lambda peer: self.assertEqual(peer.recv(1), b""))
                    result = cli(verb, devnull=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    server.result(timeout=3)

    def test_cli_lifecycle(self):
        # Use a sleeping child to exercise the real launch/stop protocol without
        # the guest closure. Real QEMU boot is a separate integration check.
        cogbox = os.environ["COGBOX"]
        runner = self.root / "runner" / "bin"
        runner.mkdir(parents=True)
        script = runner / "microvm-run"
        script.write_text("#!/bin/sh\nexec sleep 300\n")
        script.chmod(0o755)
        runtime = self.root / "run"
        runtime.mkdir()
        env = dict(os.environ, HOME=str(self.root), XDG_CONFIG_HOME=str(self.root / "config"),
                   XDG_DATA_HOME=str(self.root / "data"), XDG_RUNTIME_DIR=str(runtime),
                   RUNNER_DIR=str(runner.parent))
        def cli(*args):
            return subprocess.run([cogbox, *args], env=env, capture_output=True, text=True, timeout=80)
        def diagnostics():
            log = runtime / "cogbox/cogbox.log"
            return log.read_text()[-12000:] if log.exists() else "no launcher log"
        p = cli("init", "--yes", "--no-auto-keys")
        self.assertEqual(p.returncode, 0, p.stderr)
        config = json.loads((self.root / "config/cogbox/instances/default/config.json").read_text())
        self.assertEqual((config["vcpu"], config["mem"]), (4, 8192))
        self.assertEqual(cli("status").returncode, 3)
        try:
            p = cli("start", "--no-ssh", "--network", "none")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(cli("status").returncode, 0)
            self.assertEqual(cli("start", "--no-ssh").returncode, 75)
            # A request retained from another launch may never stop this one.
            with (runtime / "cogbox/control").open("w") as control:
                control.write("00000000-0000-0000-0000-000000000000 force\n")
            time.sleep(0.2)
            self.assertEqual(cli("status").returncode, 0)
            p = cli("stop")
            self.assertEqual(p.returncode, 0, p.stderr + diagnostics())
            self.assertEqual(cli("status").returncode, 3)
            self.assertEqual(cli("stop").returncode, 0)
            # Hold a fake QMP peer open so normal shutdown remains pending.
            # A second, force request must still be consumed during cleanup.
            self.assertEqual(cli("start", "--no-ssh", "--network", "none").returncode, 0)
            with socket.socket(socket.AF_UNIX) as qmp:
                qmp.bind(str(runtime / "cogbox/cogbox.socket"))
                qmp.listen()
                qmp.settimeout(5)
                stopping = self.spawn([cogbox, "stop"], env=env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
                with qmp.accept()[0] as peer:
                    peer.settimeout(5)
                    commands = b""
                    while b"system_powerdown" not in commands:
                        part = peer.recv(4096)
                        self.assertTrue(part)
                        commands += part
                    # Cross several read deadlines with a partial record.
                    nonce = (runtime / "cogbox/launch").read_text().split()[1]
                    with (runtime / "cogbox/control").open("w") as control:
                        control.write(nonce[:12]); control.flush()
                        time.sleep(0.25)
                        self.assertIsNone(stopping.poll())
                        control.write(nonce[12:] + " force\n")
                    began = time.monotonic()
                    out, err = stopping.communicate(timeout=5)
                    self.assertEqual(stopping.returncode, 0, out + err + diagnostics())
                    self.assertLess(time.monotonic() - began, 5)
                    self.assertEqual(cli("stop", "--force").returncode, 0)
            # Exercise the actual native proxy startup too, including a fresh
            # CA. A cold import must finish before fw_cfg staging/QEMU launch.
            p = cli("start", "--no-ssh", "--network", "rules")
            self.assertEqual(p.returncode, 0, p.stderr)
            ca = (runtime / "cogbox/system-l7ca").read_text()
            self.assertIn("BEGIN CERTIFICATE", ca)
            self.assertNotIn("PRIVATE KEY", ca)
            proxy_pids = [(runtime / ("cogbox/" + name)).read_text().strip()
                          for name in ("l7mitm.pid", "passt.pid", "authproxy.pid")]
            self.assertEqual(cli("stop", "--force").returncode, 0)
            for pid in proxy_pids:
                result = subprocess.run([os.environ["COGBOX_PLATFORM"], "process", pid],
                                        capture_output=True)
                self.assertEqual(result.returncode, 3, result.stdout)
        finally:
            cli("stop", "--force")


if __name__ == "__main__":
    unittest.main()
