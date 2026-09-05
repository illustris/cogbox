#!/usr/bin/env python3
"""Standing egress-floor bypass probes for cogbox container mode (TODO).

Run INSIDE the test guest AFTER cogbox-nft-divert.sh has loaded its ruleset in the
MAIN netns. The probe destinations are deliberately OFF-box: the driver puts them in
a SEPARATE peer netns reached over a veth pair and routes them via the veth next-hop,
so every probe packet leaves the main netns with oif=veth0 (NOT oif=lo). That is what
makes the test exercise the real rules -- an earlier revision pinned the dsts as local
/32s, which route via `lo`, and BOTH the nat divert (`oif "lo" return`) and the filter
floor (`oif "lo" accept`) special-case lo, so the redirect and the policy-drop never
fired and the suite codified the loopback bypass instead of the floor.

Topology (built by the driver):
  main netns: this CLIENT process + the in-pod divert-shim (127.0.0.1:18443, the local
              REDIRECT target) + a loopback raw listener (the raw positive control).
  peer netns: a SERVER instance of this script (`--serve`) that binds the enforcer,
              resolver, and per-drop-target listeners on the off-box dst addresses and
              records each delivery as a marker file under COGBOX_PROBE_HITDIR (a shared
              dir; the server is entered with `nsenter --net=...` so the filesystem -- and
              thus the marker dir -- stays common to both netns).

The client fires exactly one probe per egress path. REDIRECTED probes terminate at the
in-process shim (verified via SO_ORIGINAL_DST). DELIVERED-OFF-BOX probes (the enforcer
carve-out, the resolver-only DNS allow, and every drop case's positive control) are
observed through the shared marker dir the peer server writes. It is written to PROVE
the leaks are CLOSED: each DROPPED probe has a bound off-box listener so that -- absent
the floor -- its packet WOULD be delivered, making "no marker" a real drop signal rather
than a meaningless false pass.

Exits 0 iff every assertion holds, non-zero (with a per-line PASS/FAIL report) on any
leak. No internal identifiers: every address is from a documentation/test range (RFC 5737
TEST-NET, RFC 4193 ULA, the conventional k8s 10.96/12 ClusterIP block) and the only
hostname is under the reserved .test TLD.
"""

import os
import socket
import struct
import sys
import subprocess
import threading
import time

# --- test address plan (documentation/test ranges only) ----------------------
RESOLVER = "10.96.0.10"  # stub kube-dns ClusterIP -- the ONLY udp/53 dst allowed
ENFORCER = "10.96.12.34"  # enforcer Service ClusterIP (the nat carve-out dst)
ENF_PORT = 18443
SHIM = "127.0.0.1"  # the in-pod divert-shim REDIRECT target (LOCAL to the main netns)
SHIM_PORT = 18443
WEB = "192.0.2.10"  # raw-IP-literal TCP target (must be redirected)
NAMED_IP = "192.0.2.20"  # origin.test (in /etc/hosts) resolves here
NAMED = "origin.test"
TCP53 = "192.0.2.30"  # tcp/53 target (must be redirected, NOT sent direct)
UDP_OTHER = "198.51.100.10"  # udp/9999 target (must drop)
UDP53_BAD = "198.51.100.20"  # udp/53 to a NON-resolver (must drop)
ICMP_DST = "198.51.100.30"  # icmp echo target (must drop)
RAW_DST = "198.51.100.40"  # raw non-tcp/udp L4 target (must drop)
V6_DST = "fd00:dead:beef::10"  # any IPv6 dst (must drop)
# mosh: the peer plays the cogworxd gateway relay. MOSH_PEER:40000 seeds a flow INTO
# the main netns at 10.0.0.1:MOSH_PORT (a stand-in mosh-server echo listener there),
# whose reply must pass the floor's ct-direction-reply exception; MOSH_PEER:9999 is
# the positive-control sink for a POD-originated datagram from the same source-port
# range, which must still drop. 60005/60006 sit inside 60000-60031 = the range in
# mosh-udp-range.nix (port + count - 1), the same literal the floor script carries.
MOSH_PEER = "198.51.100.50"
MOSH_PORT = 60005  # the in-pod "mosh-server" port (peer-initiated flow, reply allowed)
MOSH_ORIG_SPORT = 60006  # pod-originated probe source port (must drop, in-range or not)
MOSH_SPOOF_SPORT = 60007  # in-range sport the raw-spoof egress reuses (must still drop)
MOSH_LOCAL = "10.0.0.1"  # the main-netns veth0 addr (a LOCAL dst -> routes via lo)
MOSH_PROBE = b"cogbox-mosh-probe"

SCTP_PROTO = 132  # IPPROTO_SCTP -- a representative non-tcp/udp IPv4 L4
SO_ORIGINAL_DST = 80  # getsockopt(SOL_IP, ...) -> the pre-REDIRECT tuple
MARK_CTL = b"COGBOX-RAW-CTL"  # loopback positive control for the raw path
MARK_DROP = b"COGBOX-RAW-DROP"  # the proto-132-to-off-box drop probe

# Shared marker dir: the peer SERVER touches a file here per delivery; the main-netns
# CLIENT polls it. The server is entered with `nsenter --net=` (NET ns only, no mount
# ns), so this path resolves to the same inode on both sides.
HITDIR = os.environ.get("COGBOX_PROBE_HITDIR", "/run/cbxprobe")
READY = "ready"  # marker the server touches once every listener is bound

# Off-box delivery markers (server side). The drop markers MUST stay absent.
M_ENF = "enf"  # tcp reached the enforcer carve-out
M_DNS = "dns_resolver"  # udp/53 reached the resolver (the one allowed datagram)
M_UDP_OTHER = "udp_other"  # udp/9999 leaked off-box
M_UDP53_BAD = "udp53_bad"  # udp/53-to-non-resolver leaked off-box
M_RAW_DROP = "raw_drop"  # proto-132 leaked off-box
M_V6_UDP = "v6_udp"  # ipv6 udp leaked off-box
M_MOSH_ORIG = "mosh_orig_leak"  # a pod-ORIGINATED sport-60006 udp datagram leaked off-box
M_MOSH_REPLY = "mosh_reply"  # the in-pod :60005 echo reached the peer (reply leg admitted)
M_MOSH_GO = "mosh_go"  # client->server control: fire the peer-initiated mosh flow now

_lock = threading.Lock()
shim_hits = []  # (ip, port) recovered from SO_ORIGINAL_DST per redirected conn
raw_ctl_seen = []  # loopback proto-132 control packets (main-netns raw listener)
_mosh_echo_sock = None  # the in-pod :MOSH_PORT echo socket, reused by the third-party probe


# --- marker helpers ----------------------------------------------------------
def _touch(name):
	try:
		open(os.path.join(HITDIR, name), "w").close()
	except OSError:
		pass


def _marker(name):
	return os.path.exists(os.path.join(HITDIR, name))


def _wait_marker(name, timeout=2.0, interval=0.05):
	end = time.time() + timeout
	while time.time() < end:
		if _marker(name):
			return True
		time.sleep(interval)
	return _marker(name)


# --- listeners: bind synchronously (so setup errors surface), serve in threads -
def _serve_tcp(family, ip, port, sink):
	s = socket.socket(family, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))
	s.listen(32)

	def loop():
		while True:
			try:
				conn, peer = s.accept()
			except OSError:
				return
			try:
				sink(conn, peer)
			except Exception:
				pass
			finally:
				try:
					conn.close()
				except OSError:
					pass

	threading.Thread(target=loop, daemon=True).start()


def _shim_sink(conn, peer):
	# In-process (main netns): recover the pre-REDIRECT dst from conntrack.
	raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
	port = struct.unpack("!H", raw[2:4])[0]
	ip = socket.inet_ntoa(raw[4:8])
	with _lock:
		shim_hits.append((ip, port))


def _serve_udp(family, ip, port, marker):
	s = socket.socket(family, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))

	def loop():
		while True:
			try:
				s.recvfrom(2048)
			except OSError:
				return
			_touch(marker)

	threading.Thread(target=loop, daemon=True).start()


def _mosh_peer_client():
	"""Peer-netns stand-in for the cogworxd gateway relay: once the client says go,
	send one datagram from MOSH_PEER:40000 to the in-pod :MOSH_PORT echo and mark
	M_MOSH_REPLY if anything comes back. The flow is seeded from OUTSIDE the main
	netns, so the echo's datagram is `ct direction reply` there -- the one UDP shape
	the floor admits from sport 60000-60031."""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((MOSH_PEER, 40000))
	s.settimeout(0.2)

	def loop():
		if not _wait_marker(M_MOSH_GO, timeout=120.0, interval=0.1):
			return
		end = time.time() + 3.0
		while time.time() < end:
			try:
				s.sendto(MOSH_PROBE, ("10.0.0.1", MOSH_PORT))
				data, _ = s.recvfrom(2048)
			except OSError:
				continue
			if data == MOSH_PROBE:
				_touch(M_MOSH_REPLY)
				return

	threading.Thread(target=loop, daemon=True).start()


def _serve_udp_echo(ip, port):
	"""Main-netns stand-in for mosh-server: echo every datagram to its sender.
	The socket is stashed in _mosh_echo_sock so the third-party probe can reuse
	the same in-range sport (now carrying an established peer-seeded flow) to try
	to reach a DIFFERENT peer."""
	global _mosh_echo_sock
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((ip, port))
	_mosh_echo_sock = s

	def loop():
		while True:
			try:
				data, peer = s.recvfrom(2048)
				s.sendto(data, peer)
			except OSError:
				return

	threading.Thread(target=loop, daemon=True).start()


def _serve_raw(sink):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, SCTP_PROTO)

	def loop():
		while True:
			try:
				data, _ = s.recvfrom(65535)
			except OSError:
				return
			sink(bytes(data))

	threading.Thread(target=loop, daemon=True).start()


# --- helpers -----------------------------------------------------------------
def _tcp_connect(host, port, timeout=2.0):
	conn = socket.create_connection((host, port), timeout=timeout)
	conn.close()


def _udp_send(family, ip, port, payload=b"cogbox-probe"):
	s = socket.socket(family, socket.SOCK_DGRAM)
	try:
		s.sendto(payload, (ip, port))
	except OSError:
		pass
	finally:
		s.close()


def _raw_send(ip, payload):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, SCTP_PROTO)
	try:
		s.sendto(payload, (ip, 0))
	except OSError:
		pass
	finally:
		s.close()


def _ip_checksum(data):
	if len(data) % 2:
		data += b"\x00"
	total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
	total = (total >> 16) + (total & 0xFFFF)
	total += total >> 16
	return (~total) & 0xFFFF


def _raw_send_udp(dst_ip, dst_port, src_ip, src_port, payload=MOSH_PROBE):
	"""Send ONE UDP datagram with a SPOOFED source via an IP_HDRINCL raw socket
	(needs CAP_NET_RAW; the VM test runs as root). This is finding-1's attack
	primitive: a datagram src<A> -> <local>:<in-range> routes via lo and, absent
	the prerouting mark, seeds a conntrack entry whose reply tuple <local>:<port>
	-> <A> a pod-originated egress can then ride. The UDP checksum is left 0
	(optional on IPv4)."""
	saddr = socket.inet_aton(src_ip)
	daddr = socket.inet_aton(dst_ip)
	udp_len = 8 + len(payload)
	udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
	total_len = 20 + udp_len
	ip = struct.pack(
		"!BBHHHBBH4s4s",
		0x45, 0, total_len, 0, 0, 64, socket.IPPROTO_UDP, 0, saddr, daddr,
	)
	ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	try:
		s.sendto(ip + udp, (dst_ip, 0))
	except OSError:
		pass
	finally:
		s.close()


# --- probes: FORCED-THROUGH (redirected to the shim w/ correct orig dst) ------
def probe_forced_tcp_literal():
	_tcp_connect(WEB, 443)
	return _wait_until_shim(WEB, 443)


def probe_forced_tcp_name():
	_tcp_connect(NAMED, 80)  # resolves via /etc/hosts -> NAMED_IP
	return _wait_until_shim(NAMED_IP, 80)


def probe_forced_tcp_port53():
	# tcp/53 must be REDIRECTED (enforced), never confused with the udp/53 DNS
	# carve-out and sent direct.
	_tcp_connect(TCP53, 53)
	return _wait_until_shim(TCP53, 53)


def _wait_until_shim(ip, port, timeout=2.0, interval=0.05):
	end = time.time() + timeout
	while time.time() < end:
		with _lock:
			if (ip, port) in shim_hits:
				return True
		time.sleep(interval)
	with _lock:
		return (ip, port) in shim_hits


# --- probes: ENFORCER CARVE-OUT ----------------------------------------------
def probe_enforcer_carveout():
	# TCP to the enforcer ClusterIP:base RETURNs (anti-loop), is NOT redirected,
	# and reaches the off-box enforcer listener directly.
	_tcp_connect(ENFORCER, ENF_PORT)
	reached = _wait_marker(M_ENF)
	with _lock:
		not_redirected = (ENFORCER, ENF_PORT) not in shim_hits
	return reached and not_redirected


def probe_enforcer_other_port_redirected():
	# Same ClusterIP, a DIFFERENT port: not the carve-out, so it IS redirected.
	_tcp_connect(ENFORCER, 9999)
	return _wait_until_shim(ENFORCER, 9999)


# --- probes: ALLOWED ---------------------------------------------------------
def probe_udp_resolver_allowed():
	_udp_send(socket.AF_INET, RESOLVER, 53)
	return _wait_marker(M_DNS)


# --- probes: DROPPED / now CLOSED (must fail to be delivered off-box) ---------
def probe_udp_other_dropped():
	_udp_send(socket.AF_INET, UDP_OTHER, 9999)
	return not _wait_marker(M_UDP_OTHER, timeout=1.0)


def probe_udp53_nonresolver_dropped():
	# The DNS-tunnel/exfil leak: udp/53 to ANY non-resolver IP must now drop.
	_udp_send(socket.AF_INET, UDP53_BAD, 53)
	return not _wait_marker(M_UDP53_BAD, timeout=1.0)


def probe_icmp_dropped():
	# ICMP echo to an off-box IP would normally get a reply from the peer netns;
	# the floor drops it at OUTPUT (oif=veth0, l4proto != tcp), so ping fails.
	r = subprocess.run(
		["ping", "-c", "1", "-W", "1", ICMP_DST],
		stdout=subprocess.DEVNULL,
		stderr=subprocess.DEVNULL,
	)
	return r.returncode != 0


def probe_raw_l4_dropped():
	# Positive control: proto-132 to loopback (oif lo -> floor accept) MUST be
	# delivered to the main-netns raw listener, proving the raw send/recv path works
	# in this env. The real probe: proto-132 to an OFF-box dst MUST be dropped at
	# OUTPUT, so the peer's raw listener never marks it (no SCTP/DCCP/GRE egress).
	_raw_send("127.0.0.1", MARK_CTL + b"\x00" * 8)
	ctl_ok = _wait_until_ctl(timeout=2.0)
	_raw_send(RAW_DST, MARK_DROP + b"\x00" * 8)
	dropped = not _wait_marker(M_RAW_DROP, timeout=1.5)
	return ctl_ok and dropped


def _wait_until_ctl(timeout=2.0, interval=0.05):
	end = time.time() + timeout
	while time.time() < end:
		with _lock:
			if any(MARK_CTL in d for d in raw_ctl_seen):
				return True
		time.sleep(interval)
	with _lock:
		return any(MARK_CTL in d for d in raw_ctl_seen)


def probe_ipv6_tcp_dropped():
	# A bound off-box v6 listener means an unfloored connect WOULD succeed; with the
	# floor the v6 OUTPUT is rejected, so connect raises.
	try:
		s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
		s.settimeout(2.0)
		s.connect((V6_DST, 80))
		s.close()
		return False  # connected -> IPv6 LEAK
	except OSError:
		return True


def probe_ipv6_udp_dropped():
	_udp_send(socket.AF_INET6, V6_DST, 53)
	return not _wait_marker(M_V6_UDP, timeout=1.0)


# --- probes: MOSH (reply leg admitted, origin leg still closed) ----------------
def probe_mosh_origin_dropped():
	# A POD-originated datagram whose SOURCE port sits inside the mosh range is
	# `ct direction original`, so the reply-only exception must not match it: the
	# peer's :9999 sink (a bound positive control) must never see it. This is the
	# check that the exception is not a sport-keyed UDP egress hole.
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.bind(("", MOSH_ORIG_SPORT))
		s.sendto(MOSH_PROBE, (MOSH_PEER, 9999))
	except OSError:
		pass
	finally:
		s.close()
	return not _wait_marker(M_MOSH_ORIG, timeout=1.0)


def probe_mosh_reply_allowed():
	# The peer (standing in for the gateway relay) seeds a flow INTO :MOSH_PORT; the
	# in-pod echo's answer is the reply leg and must reach it. Without the floor's
	# exception this datagram (udp, oif=veth0, not port 53) falls to policy drop.
	_touch(M_MOSH_GO)
	return _wait_marker(M_MOSH_REPLY, timeout=4.0)


def probe_mosh_established_no_third_party():
	# Runs AFTER probe_mosh_reply_allowed, so :MOSH_PORT now carries an established,
	# marked, peer-seeded flow. The pod reuses that SAME in-range sport to reach a
	# DIFFERENT peer/port: that is a fresh flow (ct direction original, unmarked),
	# so neither `ct direction reply` nor `ct mark 0x6d` matches and it must drop.
	# Guards against a future loosening of the reply rule to a bare `ct state
	# established`, which would pass both other mosh probes yet leak here.
	if _mosh_echo_sock is not None:
		try:
			_mosh_echo_sock.sendto(MOSH_PROBE, (MOSH_PEER, 9999))
		except OSError:
			pass
	return not _wait_marker(M_MOSH_ORIG, timeout=1.0)


def probe_mosh_raw_spoof_seed_dropped():
	# Finding-1's CAP_NET_RAW vector, proved closed by the prerouting mark. Forge a
	# lo-injected seed src MOSH_PEER:9999 -> MOSH_LOCAL:MOSH_SPOOF_SPORT (a local
	# dst, so it routes via lo and `oif "lo"` waves it through), which absent the
	# mark would leave a conntrack entry whose reply tuple an in-range-sport egress
	# can ride. Then send from that sport to MOSH_PEER:9999. Because the seed came
	# in on lo it never got ct mark 0x6d, so the reply rule refuses the egress and
	# the MOSH_PEER:9999 sink (M_MOSH_ORIG) must stay silent. (If the forged seed
	# fails to register a conntrack entry the egress simply drops as a cold
	# original datagram -- still no marker, never a false failure.)
	_raw_send_udp(MOSH_LOCAL, MOSH_SPOOF_SPORT, MOSH_PEER, 9999)
	time.sleep(0.2)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		s.bind(("", MOSH_SPOOF_SPORT))
		s.sendto(MOSH_PROBE, (MOSH_PEER, 9999))
	except OSError:
		pass
	finally:
		s.close()
	return not _wait_marker(M_MOSH_ORIG, timeout=1.0)


CHECKS = [
	("FORCED-THROUGH  tcp literal-IP  -> shim w/ orig dst", probe_forced_tcp_literal),
	("FORCED-THROUGH  tcp by-name      -> shim w/ orig dst", probe_forced_tcp_name),
	("FORCED-THROUGH  tcp/53           -> shim (not direct)", probe_forced_tcp_port53),
	("CARVE-OUT       tcp enforcer:base-> enforcer (RETURN)", probe_enforcer_carveout),
	("CARVE-OUT       tcp enforcer:other-> shim (redirect)", probe_enforcer_other_port_redirected),
	("ALLOWED         udp/53 -> resolver", probe_udp_resolver_allowed),
	("CLOSED          udp/9999 -> dropped", probe_udp_other_dropped),
	("CLOSED          udp/53 non-resolver -> dropped", probe_udp53_nonresolver_dropped),
	("CLOSED          icmp echo -> dropped", probe_icmp_dropped),
	("CLOSED          raw proto-132 -> dropped", probe_raw_l4_dropped),
	("CLOSED          ipv6 tcp -> dropped", probe_ipv6_tcp_dropped),
	("CLOSED          ipv6 udp -> dropped", probe_ipv6_udp_dropped),
	("CLOSED          udp sport 60006 pod-originated -> dropped", probe_mosh_origin_dropped),
	("ALLOWED         udp reply from :60005 to peer-initiated flow", probe_mosh_reply_allowed),
	("CLOSED          udp :60005 established-sport -> third party dropped", probe_mosh_established_no_third_party),
	("CLOSED          udp raw-spoof lo seed -> in-range egress dropped", probe_mosh_raw_spoof_seed_dropped),
]


def serve():
	"""Peer-netns listener server: bind the off-box dst listeners, mark deliveries.

	Runs under `nsenter --net=<peer>` so its sockets land in the peer netns while the
	marker dir stays shared with the client. Binds and then touches READY; the client
	waits for that before probing. Never exits on its own (the driver kills it)."""
	os.makedirs(HITDIR, exist_ok=True)

	def _raw_sink(data):
		if MARK_DROP in data:
			_touch(M_RAW_DROP)

	# TCP: enforcer carve-out target + a v6 target (so an unfloored v6 connect lands).
	_serve_tcp(socket.AF_INET, ENFORCER, ENF_PORT, lambda c, p: _touch(M_ENF))
	_serve_tcp(socket.AF_INET6, V6_DST, 80, lambda c, p: None)
	# UDP: the resolver (allowed) + every udp drop target (positive controls).
	_serve_udp(socket.AF_INET, RESOLVER, 53, M_DNS)
	_serve_udp(socket.AF_INET, UDP_OTHER, 9999, M_UDP_OTHER)
	_serve_udp(socket.AF_INET, UDP53_BAD, 53, M_UDP53_BAD)
	_serve_udp(socket.AF_INET6, V6_DST, 53, M_V6_UDP)
	# mosh: the sink for a pod-originated in-range-sport datagram (positive control,
	# must stay unmarked) + the gateway-relay stand-in that seeds the reply-leg flow.
	_serve_udp(socket.AF_INET, MOSH_PEER, 9999, M_MOSH_ORIG)
	_mosh_peer_client()
	# Raw proto-132 drop target.
	_serve_raw(_raw_sink)
	time.sleep(0.3)
	_touch(READY)
	while True:
		time.sleep(3600)


def main():
	# CLIENT (main netns). Bind the local REDIRECT target (shim) + the loopback raw
	# control listener, then wait for the peer server's listeners to come up.
	os.makedirs(HITDIR, exist_ok=True)
	_serve_tcp(socket.AF_INET, SHIM, SHIM_PORT, _shim_sink)

	def _ctl_sink(data):
		with _lock:
			raw_ctl_seen.append(data)

	_serve_raw(_ctl_sink)
	# mosh-server stand-in: an echo on the in-range port, bound BEFORE READY so the
	# peer's seeding datagram never races the listener.
	_serve_udp_echo("0.0.0.0", MOSH_PORT)
	if not _wait_marker(READY, timeout=15.0):
		print("FAIL  peer listener server never signalled READY")
		print("LEAK-DETECTED")
		sys.exit(1)

	ok = True
	for name, fn in CHECKS:
		try:
			result = fn()
		except Exception as exc:  # a probe blew up -> treat as failure, keep going
			result = False
			name = f"{name}  [exc: {exc!r}]"
		print(f"{'PASS' if result else 'FAIL'}  {name}")
		ok = ok and result

	print("ALL-PASS" if ok else "LEAK-DETECTED")
	sys.exit(0 if ok else 1)


if __name__ == "__main__":
	if len(sys.argv) > 1 and sys.argv[1] == "--serve":
		serve()
	else:
		main()
