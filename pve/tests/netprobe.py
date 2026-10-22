#!/usr/bin/env python3
"""Socket probes for tests/test_floor_site.sh. Stdlib only.

bash's /dev/tcp (what gce/floor.nix's verifier uses) cannot choose a source
address or port, and the site floor's rule 4 and open-ingress cases are ABOUT
the source: a reply to a control-plane address, a mosh reply from a mosh-range
port, an inbound flow from a neighbour. Hence this helper.

    netprobe.py listen tcp ADDR PORT READYFILE
        accept and close connections until killed; touches READYFILE once bound
    netprobe.py listen udp-echo ADDR PORT READYFILE
        echo each datagram back to its sender until killed
    netprobe.py listen udp-log ADDR PORT READYFILE LOGFILE
        append the source address of each datagram to LOGFILE until killed
    netprobe.py connect [--src ADDR] [--sport N] ADDR PORT
        print open | blocked | refused | eperm | error:<errno>
    netprobe.py udp [--src ADDR] [--sport N] [--expect-reply] ADDR PORT
        send one datagram; print sent | reply | noreply | eperm | error:<errno>

`blocked` is a TIMEOUT, the shape a netfilter DROP of a TCP SYN (or of its
SYN-ACK) takes: the kernel retransmits and connect() never completes. A port
with no listener answers RST at once (`refused`). A UDP datagram dropped on
OUTPUT fails the send itself (`eperm`).
"""

import argparse
import errno
import os
import socket
import sys

TIMEOUT = float(os.environ.get("NETPROBE_TIMEOUT", "1.5"))


def _bind(sock, src, sport):
    if src or sport:
        sock.bind((src or "0.0.0.0", sport or 0))


def listen(kind, addr, port, ready, log=None):
    if kind == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen(16)
        open(ready, "w").close()
        while True:
            c, _ = s.accept()
            c.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    open(ready, "w").close()
    while True:
        data, peer = s.recvfrom(2048)
        if kind == "udp-echo":
            s.sendto(data, peer)
        else:
            with open(log, "a") as f:
                f.write("%s\n" % peer[0])


def connect(addr, port, src, sport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(TIMEOUT)
    try:
        _bind(s, src, sport)
        s.connect((addr, port))
        return "open"
    except socket.timeout:
        return "blocked"
    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            return "refused"
        if e.errno == errno.EPERM:
            return "eperm"
        return "error:%s" % errno.errorcode.get(e.errno, e.errno)
    finally:
        s.close()


def udp(addr, port, src, sport, expect_reply):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        _bind(s, src, sport)
        s.sendto(b"netprobe", (addr, port))
        if not expect_reply:
            return "sent"
        s.recvfrom(2048)
        return "reply"
    except socket.timeout:
        return "noreply"
    except OSError as e:
        if e.errno == errno.EPERM:
            return "eperm"
        return "error:%s" % errno.errorcode.get(e.errno, e.errno)
    finally:
        s.close()


def main(argv):
    p = argparse.ArgumentParser(prog="netprobe.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("listen")
    pl.add_argument("kind", choices=["tcp", "udp-echo", "udp-log"])
    pl.add_argument("addr")
    pl.add_argument("port", type=int)
    pl.add_argument("ready")
    pl.add_argument("log", nargs="?")
    for name in ("connect", "udp"):
        pc = sub.add_parser(name)
        pc.add_argument("--src")
        pc.add_argument("--sport", type=int)
        if name == "udp":
            pc.add_argument("--expect-reply", action="store_true")
        pc.add_argument("addr")
        pc.add_argument("port", type=int)
    a = p.parse_args(argv)
    if a.cmd == "listen":
        if a.kind == "udp-log" and not a.log:
            p.error("udp-log needs LOGFILE")
        listen(a.kind, a.addr, a.port, a.ready, a.log)
        return 0
    if a.cmd == "connect":
        print(connect(a.addr, a.port, a.src, a.sport))
    else:
        print(udp(a.addr, a.port, a.src, a.sport, a.expect_reply))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
