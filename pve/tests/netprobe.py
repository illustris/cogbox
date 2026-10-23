#!/usr/bin/env python3
"""Socket probes for tests/test_floor_site.sh. Stdlib only.

bash's /dev/tcp (what gce/floor.nix's verifier uses) cannot choose a source
address, and the site floor's rule 4a, rule 4 reply and open-ingress cases
are ABOUT the source: a link-local source leaving the NIC, a neighbour's
datagram for the metadata address, a reply to an internal address, an
inbound flow from a neighbour. Hence this helper. TCP and `udp` take an IPv6
address too (rule 4's ::1 legs); the family follows the address. `udp` may
send to a broadcast address (SO_BROADCAST is set on every IPv4 datagram
socket) and to a multicast group, which with --src leaves by the interface
that owns the source address (rule 4's broadcast and multicast drop).

    netprobe.py listen tcp ADDR PORT READYFILE
        accept and close connections until killed; touches READYFILE once bound
    netprobe.py listen udp-log ADDR PORT READYFILE LOGFILE
        append the source address of each datagram to LOGFILE until killed
        (IPv4 only; 0.0.0.0 stands for a wildcard agent)
    netprobe.py connect [--src ADDR] ADDR PORT
        print open | blocked | refused | eperm | error:<errno>
    netprobe.py udp [--src ADDR] ADDR PORT
        send one datagram; print sent | eperm | error:<errno>

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


def _family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def _bind(sock, src):
    if src:
        sock.bind((src, 0))


def listen(kind, addr, port, ready, log=None):
    if kind == "tcp":
        s = socket.socket(_family(addr), socket.SOCK_STREAM)
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
        _, peer = s.recvfrom(2048)
        with open(log, "a") as f:
            f.write("%s\n" % peer[0])


def connect(addr, port, src):
    s = socket.socket(_family(addr), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(TIMEOUT)
    try:
        _bind(s, src)
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


def udp(addr, port, src):
    s = socket.socket(_family(addr), socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    if s.family == socket.AF_INET:
        # Without it a send to a broadcast address fails with EACCES before
        # any hook sees it; a unicast or multicast send is unaffected.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        _bind(s, src)
        s.sendto(b"netprobe", (addr, port))
        return "sent"
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
    pl.add_argument("kind", choices=["tcp", "udp-log"])
    pl.add_argument("addr")
    pl.add_argument("port", type=int)
    pl.add_argument("ready")
    pl.add_argument("log", nargs="?")
    for name in ("connect", "udp"):
        pc = sub.add_parser(name)
        pc.add_argument("--src")
        pc.add_argument("addr")
        pc.add_argument("port", type=int)
    a = p.parse_args(argv)
    if a.cmd == "listen":
        if a.kind == "udp-log" and not a.log:
            p.error("udp-log needs LOGFILE")
        listen(a.kind, a.addr, a.port, a.ready, a.log)
        return 0
    if a.cmd == "connect":
        print(connect(a.addr, a.port, a.src))
    else:
        print(udp(a.addr, a.port, a.src))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
