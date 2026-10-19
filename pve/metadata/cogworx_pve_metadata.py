#!/usr/bin/env python3
"""cogworx-pve-metadata: the local GCE-metadata emulator of a cogbox PVE host.

The gce/ host half talks to the outside world through exactly one interface,
the GCE metadata server at 169.254.169.254, and five of its units hard-code
that URL. On Proxmox there is no metadata server, so this process provides the
subset gce/ actually uses, bound on 169.254.169.254/32 scope host dev lo and
started by systemd socket activation. gce/ runs unchanged on top of it.

INBOUND (control plane -> VM): one SMBIOS type-1 `serial`, written by cogworxd
into the stopped VM's `smbios1` as `uuid=<owner>,base64=1,serial=<b64(blob)>`.
The blob is a versioned application/x-www-form-urlencoded string (boot config
v1, below). PVE decodes base64=1 values before handing them to QEMU, so the
guest sees the RAW blob in /sys/class/dmi/id/product_serial, as confirmed on a
live PVE VM. Acceptance of its base64 encoding is kept for compatibility, so
both forms are accepted:

  (a) the raw blob, `...&v=1&w=rules` (what PVE delivers);
  (b) its standard base64 encoding.

Classification is unambiguous for every blob this decoder would accept: an
accepted blob carries `v=1`, so it either has a second field (and therefore a
`&`, which is outside the base64 alphabet) or it is exactly `v=1`, whose length
is not a multiple of four. A serial that strictly base64-decodes to printable
ASCII is therefore form (b) and anything else is form (a). Checking the decoded
text for printability rather than for a `v=1` field keeps the rejection REASON
identical across both carriers (a `v=2` blob is "bad-version" either way).

OUTBOUND (VM -> control plane): guest attributes. Every mutation atomically
rewrites /run/cogworx/guest-attributes.json, which cogworxd reads through the
QEMU guest agent's file-read:

  {"v":1,"boot_id":"<kernel boot id>","gen":N,"sys":"<booted system>","attrs":{"<ns>/<key>":"<value>"}}

`gen` counts mutations within one boot. A restarted emulator re-adopts the file
only when its boot_id matches this boot, so attributes survive a service
restart but never a reboot.

`sys` is the booted NixOS system (the toplevel /run/booted-system resolves to),
read ONCE when the emulator starts. It is ABSENT, never null, when unknown: the
link is missing or does not resolve to a /nix/store/...-nixos-system-... path.
A restart re-adopts the attributes only; `sys` is always this process's own
reading. `v` stays 1 (readers ignore unknown keys, and a bump would make
cogworxd's parser reject the file). cogworxd ignores `sys` today; it is there
for the in-place upgrade resolver, which needs to know which system generation
a VM booted (docs/pve-system-upgrade.md).

Boot config v1 (Go encodes with url.Values.Encode, the reference encoder below
uses urlencode(sorted(...), quote_via=quote_plus); both produce keys in byte
order and escape the same set):

  code  served as instance/attributes/...   value
  v     (none)                               exactly "1"; required
  n     cogworx-start-nonce                  lowercase RFC 4122 UUID
  i     cogworx-instance                     [a-zA-Z][a-zA-Z0-9-]{0,63}
  p     cogworx-ssh-principal                [A-Za-z0-9._-]{1,81}
  K     cogworx-ssh-ca-pub                   base64url (unpadded, 68 chars) of
                                             the 51-byte ed25519 wire blob;
                                             served re-encoded as standard
                                             base64 behind "ssh-ed25519 "
  h     cogworx-hostname                     [a-z][a-z0-9-]{0,7}[0-9]{1,9}
  c     cogworx-vcpu                         [1-9][0-9]{0,2}
  m     cogworx-mem-mb                       [1-9][0-9]{0,6}
  w     cogworx-network                      rules | none  (full is refused)
  g     cogworx-guest-resolver               canonical dotted-quad IPv4
  M     cogworx-maintenance                  flag: the value must be empty; it
                                             is served as an empty 200 body
  R D s reserved for resolver boots; never emitted in v1, so they are ignored
        here like any unknown key and are never served

Decode rules, checked in this order; the first failure rejects the WHOLE blob
and the reason string is a contract shared with the Go decoder:

  1. charset: only [A-Za-z0-9._~+=&-] and %XX (two hex digits) -> parse-error
  2. at most 32 '&'-separated fields                        -> too-many-fields
  3. parse_qsl(strict_parsing=True, keep_blank_values=True, max_num_fields=32,
     errors="strict"): every field has '=', no empty field; the decoded name is
     non-empty and every %XX run decodes as UTF-8           -> parse-error
  4. a decoded key appears twice                            -> duplicate-key
  5. v absent                                               -> missing-version
     v present but not exactly "1"                          -> bad-version
  6. each known code present, in byte order (K M c g h i m n p w), must match
     its grammar above                                      -> invalid-value:<code>

Unknown keys are ignored and logged by name. An empty serial means NO blob,
which is not a rejection: attributes then return 404 while instance/id still
returns 200. A rejected blob is served exactly like no blob, after one loud
log line naming the reason.

HTTP subset (http://169.254.169.254/computeMetadata/v1/...), HTTP/1.0 with
Content-Length, every response carrying `Metadata-Flavor: Google`:

  - Refusals, checked in this order: 403 when the peer is not uid 0 (resolved
    through /proc/net/tcp from the client socket's live row; a client that
    has already closed its socket, whose row reads uid 0 inode 0, is refused
    too); 403 when an X-Forwarded-For header is present; 405
    for any method other than GET/PUT/DELETE; 400 for a query string, `%` or
    `..` anywhere in the target; 403 unless exactly one `Metadata-Flavor:
    Google` header is present. Unknown paths are 404, and a method a known
    path does not take is 405.
  - GET instance/id -> the SMBIOS uuid, lowercased.
  - GET instance/attributes/{k} -> the value, or 404 exactly when absent.
  - GET instance/network-interfaces/ -> "0/\\n" once eth0 has a usable IPv4,
    waiting up to 8 s, else 503; GET .../0/ip -> that address or 503; any other
    index is 404.
  - GET/PUT/DELETE instance/guest-attributes/{ns}/{key}: PUT bodies are at most
    1024 bytes of UTF-8 and the store holds at most 64 keys (413 beyond either,
    400 for a malformed body); DELETE is idempotent.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import http.server
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
import urllib.parse

LOG = logging.getLogger("cogworx-pve-metadata")

# --- boot config v1 ---------------------------------------------------------

SMBIOS1_MAX_LEN = 512
MAX_FIELDS = 32

# code -> the instance attribute the gce/ units read it as.
ATTRIBUTES = {
    "K": "cogworx-ssh-ca-pub",
    "M": "cogworx-maintenance",
    "c": "cogworx-vcpu",
    "g": "cogworx-guest-resolver",
    "h": "cogworx-hostname",
    "i": "cogworx-instance",
    "m": "cogworx-mem-mb",
    "n": "cogworx-start-nonce",
    "p": "cogworx-ssh-principal",
    "w": "cogworx-network",
}
# Resolver-boot keys. v1 never emits them; serving them would let a blob turn a
# sandbox boot into a resolver boot, so they stay unknown on purpose.
RESERVED = frozenset({"R", "D", "s"})

REJECT_REASONS = (
    "parse-error",
    "too-many-fields",
    "duplicate-key",
    "missing-version",
    "bad-version",
) + tuple("invalid-value:" + code for code in sorted(ATTRIBUTES))

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
# Every grammar is fullmatch()ed. Together they bound the blob: the worst case
# is 329 raw bytes, 498 characters of smbios1 once wrapped (README.md, Inbound).
VALUE_GRAMMAR = {
    "K": re.compile(r"[A-Za-z0-9_-]{68}"),
    "M": re.compile(r""),
    "c": re.compile(r"[1-9][0-9]{0,2}"),
    "g": re.compile(_OCTET + r"(?:\." + _OCTET + r"){3}"),
    "h": re.compile(r"[a-z][a-z0-9-]{0,7}[0-9]{1,9}"),
    "i": re.compile(r"[a-zA-Z][a-zA-Z0-9-]{0,63}"),
    "m": re.compile(r"[1-9][0-9]{0,6}"),
    "n": re.compile(_UUID),
    "p": re.compile(r"[A-Za-z0-9._-]{1,81}"),
    "w": re.compile(r"rules|none"),
}
_BLOB_CHARSET = re.compile(r"(?:[A-Za-z0-9._~+=&-]|%[0-9A-Fa-f]{2})*")
_UUID_RE = re.compile(_UUID)

# The 19-byte prefix of every ed25519 public key in SSH wire form: a
# length-prefixed "ssh-ed25519", then the length of the 32-byte key.
ED25519_WIRE_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
ED25519_WIRE_LEN = len(ED25519_WIRE_PREFIX) + 32


class BootConfigRejected(ValueError):
    """The whole blob is refused; `reason` is one of REJECT_REASONS."""

    def __init__(self, reason, detail=""):
        super().__init__(reason + (": " + detail if detail else ""))
        self.reason = reason


def k_to_ssh_line(k):
    """Re-encode the `K` payload as the authorized-key line gce/ stages."""
    wire = base64.b64decode(k.replace("-", "+").replace("_", "/"), validate=True)
    if len(wire) != ED25519_WIRE_LEN or not wire.startswith(ED25519_WIRE_PREFIX):
        raise ValueError("not an ed25519 public key in SSH wire form")
    return "ssh-ed25519 " + base64.b64encode(wire).decode("ascii")


def ssh_line_to_k(line):
    """The inverse of k_to_ssh_line, for the reference encoder."""
    parts = line.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("not an ssh-ed25519 authorized-key line")
    wire = base64.b64decode(parts[1], validate=True)
    if len(wire) != ED25519_WIRE_LEN or not wire.startswith(ED25519_WIRE_PREFIX):
        raise ValueError("not an ed25519 public key in SSH wire form")
    return base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")


def decode_blob(blob):
    """Decode a boot config v1 blob into {attribute name: served value}.

    Raises BootConfigRejected. An empty blob is "no blob" and yields {}.
    """
    if blob == "":
        return {}
    if not _BLOB_CHARSET.fullmatch(blob):
        raise BootConfigRejected("parse-error", "character outside the form-encoding set")
    if blob.count("&") + 1 > MAX_FIELDS:
        raise BootConfigRejected("too-many-fields", "more than %d fields" % MAX_FIELDS)
    try:
        pairs = urllib.parse.parse_qsl(
            blob,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=MAX_FIELDS,
            errors="strict",
        )
    except ValueError as e:  # UnicodeDecodeError is a ValueError too
        raise BootConfigRejected("parse-error", str(e)) from None
    fields = {}
    for key, value in pairs:
        if key == "":
            raise BootConfigRejected("parse-error", "empty key")
        if key in fields:
            raise BootConfigRejected("duplicate-key", "key %r appears twice" % key[:32])
        fields[key] = value
    if "v" not in fields:
        raise BootConfigRejected("missing-version")
    if fields["v"] != "1":
        raise BootConfigRejected("bad-version", "v=%r" % fields["v"][:16])
    attrs = {}
    for code in sorted(ATTRIBUTES):
        if code not in fields:
            continue
        value = fields[code]
        if not VALUE_GRAMMAR[code].fullmatch(value):
            raise BootConfigRejected("invalid-value:" + code)
        if code == "K":
            try:
                value = k_to_ssh_line(value)
            except (ValueError, binascii.Error):
                raise BootConfigRejected("invalid-value:K") from None
        attrs[ATTRIBUTES[code]] = value
    for key in sorted(set(fields) - set(ATTRIBUTES) - {"v"}):
        if key in RESERVED:
            LOG.warning("boot config: ignoring reserved key %r (never emitted in v1)", key)
        else:
            LOG.warning("boot config: ignoring unknown key %r", key[:32])
    return attrs


# The reference encoder. cogworxd's Go encoder is authoritative in production;
# this one exists so the shared vectors can be proven canonical from this side,
# and for the bake smoke clone. bootconfig keys are the vector-file field names.
BOOTCONFIG_FIELDS = (
    ("nonce", "n"),
    ("instance", "i"),
    ("principal", "p"),
    ("ssh_ca_pub", "K"),
    ("hostname", "h"),
    ("vcpu", "c"),
    ("mem_mb", "m"),
    ("network", "w"),
    ("guest_resolver", "g"),
    ("maintenance", "M"),
)


def encode_blob(bootconfig):
    known = dict(BOOTCONFIG_FIELDS)
    extra = sorted(set(bootconfig) - set(known))
    if extra:
        raise ValueError("unknown bootconfig fields: %s" % ", ".join(extra))
    fields = [("v", "1")]
    for name, code in BOOTCONFIG_FIELDS:
        value = bootconfig.get(name)
        if value is None or value is False or value == "":
            continue
        if code == "M":
            if value is not True:
                raise ValueError("maintenance must be a boolean")
            fields.append(("M", ""))
        elif code == "K":
            fields.append(("K", ssh_line_to_k(value)))
        elif code == "w" and value == "full":
            raise ValueError("network=full is refused on Proxmox")
        else:
            fields.append((code, str(value)))
    blob = urllib.parse.urlencode(sorted(fields), quote_via=urllib.parse.quote_plus)
    decode_blob(blob)  # the encoder never emits what the decoder would refuse
    return blob


def encode_smbios1(owner_uuid, blob):
    """The `smbios1` value: owner-only when there is no blob (Provision)."""
    if not _UUID_RE.fullmatch(owner_uuid):
        raise ValueError("owner uuid must be a lowercase RFC 4122 UUID")
    if blob == "":
        value = "uuid=" + owner_uuid
    else:
        value = "uuid=%s,base64=1,serial=%s" % (
            owner_uuid,
            base64.b64encode(blob.encode("ascii")).decode("ascii"),
        )
    if len(value) > SMBIOS1_MAX_LEN:
        raise ValueError("smbios1 is %d characters, over the %d cap" % (len(value), SMBIOS1_MAX_LEN))
    return value


def unwrap_serial(raw):
    """The blob carried by the SMBIOS serial bytes, in either form (a) or (b)."""
    try:
        text = raw.decode("ascii").strip(" \t\r\n\x00")
    except UnicodeDecodeError:
        raise BootConfigRejected("parse-error", "SMBIOS serial is not ASCII") from None
    if text == "":
        return ""
    try:
        inner = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return text
    if inner and all(0x21 <= b <= 0x7E for b in inner):
        return inner.decode("ascii")
    return text


def read_boot_attrs(serial_path):
    """Read and decode this boot's SMBIOS serial; never raises.

    Returns the served attributes ({} for no blob and for a rejected blob, which
    is logged loudly with its reason).
    """
    try:
        with open(serial_path, "rb") as f:
            raw = f.read(8192)
    except FileNotFoundError:
        LOG.info("boot config: %s is absent; serving no attributes", serial_path)
        return {}
    except OSError as e:
        LOG.error("boot config: cannot read %s (%s); serving no attributes", serial_path, e.strerror)
        return {}
    try:
        blob = unwrap_serial(raw)
        if blob == "":
            LOG.info("boot config: SMBIOS serial is empty; serving no attributes")
            return {}
        attrs = decode_blob(blob)
    except BootConfigRejected as e:
        LOG.error("boot config: REJECTED (%s); serving no attributes", e)
        return {}
    LOG.info("boot config: v1 accepted, serving %s", ", ".join(sorted(attrs)) or "no attributes")
    return attrs


def read_instance_id(uuid_path):
    """The SMBIOS uuid, lowercased; None when unreadable or malformed."""
    try:
        with open(uuid_path, "rb") as f:
            value = f.read(128).decode("ascii", "replace").strip().lower()
    except OSError as e:
        LOG.error("instance id: cannot read %s (%s)", uuid_path, e.strerror)
        return None
    if not _UUID_RE.fullmatch(value):
        LOG.error("instance id: %s does not hold a UUID", uuid_path)
        return None
    return value


def read_boot_id(path="/proc/sys/kernel/random/boot_id"):
    with open(path, "r", encoding="ascii") as f:
        return f.read().strip()


# --- guest attributes ---------------------------------------------------------

STATE_FILE = "guest-attributes.json"
GA_MAX_KEYS = 64
GA_MAX_VALUE = 1024
_GA_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
# A NixOS toplevel store path, the upgrade tool's grammar for one.
_SYSTEM_RE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-nixos-system-[A-Za-z0-9._+-]{1,200}")


def read_booted_system(path="/run/booted-system"):
    """The booted system's store path, or None when it is unknown.

    Unknown means the link is missing or resolves to anything but a NixOS
    toplevel store path; the caller then leaves `sys` out of the state file.
    """
    target = os.path.realpath(path)
    if not _SYSTEM_RE.fullmatch(target):
        LOG.warning("booted system: %s does not resolve to a NixOS system; leaving sys out", path)
        return None
    return target


class LimitExceeded(Exception):
    pass


class GuestAttributeStore:
    """The guest-attribute map, persisted to <state_dir>/guest-attributes.json.

    The file is the ONLY thing cogworxd sees, so memory never runs ahead of it:
    a mutation computes the new map, writes it to a temporary file in the same
    directory, renames it over the old one and only then commits it in memory.
    A failed write leaves both the file and the served map as they were.
    """

    def __init__(self, state_dir, boot_id, booted_system=None):
        self._dir = state_dir
        self._path = os.path.join(state_dir, STATE_FILE)
        self._boot_id = boot_id
        self._booted_system = booted_system
        self._lock = threading.Lock()
        self._attrs = {}
        self._gen = 0
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
        self._load()

    @property
    def path(self):
        return self._path

    def _load(self):
        try:
            with open(self._path, "rb") as f:
                doc = json.loads(f.read())
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            LOG.warning("guest attributes: discarding unreadable %s (%s)", self._path, e)
            self._persist({}, 0)
            return
        attrs = _valid_state(doc)
        if attrs is None:
            LOG.warning("guest attributes: discarding malformed %s", self._path)
            self._persist({}, 0)
        elif doc["boot_id"] != self._boot_id:
            LOG.warning("guest attributes: discarding %s from another boot", self._path)
            self._persist({}, 0)
        else:
            # The attributes only: a `sys` in the file is never taken over.
            self._attrs, self._gen = attrs, doc["gen"]
            LOG.info("guest attributes: re-adopted %d attribute(s) at gen %d from this boot", len(attrs), self._gen)

    def _persist(self, attrs, gen):
        doc = {"v": 1, "boot_id": self._boot_id, "gen": gen}
        if self._booted_system is not None:
            doc["sys"] = self._booted_system
        doc["attrs"] = dict(sorted(attrs.items()))
        data = (json.dumps(doc, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        fd, tmp = tempfile.mkstemp(prefix=".guest-attributes.", suffix=".tmp", dir=self._dir)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    def get(self, key):
        with self._lock:
            return self._attrs.get(key)

    def put(self, key, value):
        # The handler has already enforced both bounds; repeating them here
        # keeps the store from ever writing a file that _load would discard.
        ns, _, name = key.partition("/")
        if not (_GA_NAME.fullmatch(ns) and _GA_NAME.fullmatch(name)):
            raise ValueError("malformed guest attribute key %r" % key[:140])
        if len(value.encode("utf-8")) > GA_MAX_VALUE:
            raise LimitExceeded("value exceeds %d bytes" % GA_MAX_VALUE)
        with self._lock:
            if key not in self._attrs and len(self._attrs) >= GA_MAX_KEYS:
                raise LimitExceeded("the store already holds %d keys" % GA_MAX_KEYS)
            attrs = dict(self._attrs)
            attrs[key] = value
            self._persist(attrs, self._gen + 1)
            self._attrs, self._gen = attrs, self._gen + 1

    def delete(self, key):
        """Idempotent. Returns whether the key existed (only then is the file rewritten)."""
        with self._lock:
            if key not in self._attrs:
                return False
            attrs = dict(self._attrs)
            del attrs[key]
            self._persist(attrs, self._gen + 1)
            self._attrs, self._gen = attrs, self._gen + 1
            return True


def _valid_state(doc):
    """The attrs of a well-formed state document, else None."""
    if not isinstance(doc, dict) or doc.get("v") != 1:
        return None
    gen = doc.get("gen")
    if not isinstance(doc.get("boot_id"), str) or type(gen) is not int or gen < 0:
        return None
    attrs = doc.get("attrs")
    if not isinstance(attrs, dict) or len(attrs) > GA_MAX_KEYS:
        return None
    for key, value in attrs.items():
        ns, _, name = key.partition("/")
        if not (_GA_NAME.fullmatch(ns) and _GA_NAME.fullmatch(name)):
            return None
        if not isinstance(value, str) or len(value.encode("utf-8", "surrogatepass")) > GA_MAX_VALUE:
            return None
    return attrs


# --- peer credentials -----------------------------------------------------------

# Only these client-side states carry the owning socket's uid. A TIME_WAIT or
# SYN_RECV entry reports uid 0 whoever opened it, so admitting one would fail
# OPEN; a client is ESTABLISHED (or half-closed) while its request is served.
#
# The state alone is not enough. A client that writes its whole request and
# then close()s leaves an ORPHANED socket in FIN_WAIT1/FIN_WAIT2 -- no file,
# so the kernel prints it as uid 0 with inode 0 -- and the request is still in
# our receive buffer to be served. Only a row with a non-zero inode is still
# owned by a process, so a row with inode 0 never names a uid.
_TCP_LIVE_STATES = frozenset({"01", "04", "05"})  # ESTABLISHED, FIN_WAIT1, FIN_WAIT2


def _proc_hexaddr(addr):
    """An (ip, port) as /proc/net/tcp prints it: the __be32 read natively."""
    packed = socket.inet_aton(addr[0])
    return "%08X:%04X" % (struct.unpack("=I", packed)[0], addr[1])


def match_proc_net_tcp(text, client, server):
    """The uid owning the CLIENT end of the connection client -> server.

    That socket's /proc/net/tcp row has local_address == client and
    rem_address == server. None unless exactly one live row (or several that
    agree) names a uid; a row is live when its state is in _TCP_LIVE_STATES
    AND it still has an inode (an orphaned socket prints uid 0, inode 0).
    """
    try:
        want_local, want_rem = _proc_hexaddr(client), _proc_hexaddr(server)
    except (OSError, TypeError, ValueError, IndexError):
        return None  # not IPv4: fail closed
    uids = set()
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10 or f[1].upper() != want_local or f[2].upper() != want_rem:
            continue
        if f[3].upper() not in _TCP_LIVE_STATES:
            continue
        try:
            uid, inode = int(f[7]), int(f[9])
        except ValueError:
            return None
        if inode == 0:
            continue  # orphaned: closed by its owner, printed as uid 0
        uids.add(uid)
    return uids.pop() if len(uids) == 1 else None


def proc_peer_uid(server, client, path="/proc/net/tcp"):
    try:
        with open(path, "r", encoding="ascii") as f:
            text = f.read()
    except OSError as e:
        LOG.error("peer uid: cannot read %s (%s)", path, e.strerror)
        return None
    return match_proc_net_tcp(text, client, server)


# --- interface address ----------------------------------------------------------

SIOCGIFADDR = 0x8915


def iface_ipv4(iface):
    """The primary IPv4 address of `iface`, or None (no address, no interface)."""
    name = iface.encode("ascii", "replace")
    if not name or len(name) > 15:
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", name))
        except OSError:
            return None
    # struct ifreq: 16-byte name, then a sockaddr_in whose address is at +4.
    return socket.inet_ntoa(res[20:24])


def usable_ipv4(value):
    """A DHCP address worth serving. Never link-local: 169.254.169.254 is ours."""
    try:
        ip = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError, ValueError):
        return False
    return not (ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved)


# --- HTTP ---------------------------------------------------------------------

PREFIX = "/computeMetadata/v1/"
_ATTR_PATH = re.compile(r"instance/attributes/([A-Za-z0-9._-]{1,128})")
_GA_PATH = re.compile(r"instance/guest-attributes/([A-Za-z0-9_-]{1,64})/([A-Za-z0-9_-]{1,64})")
_CONTENT_LENGTH = re.compile(r"[0-9]{1,9}")


class Metadata:
    """Everything a request handler consults; one instance per process."""

    def __init__(self, *, instance_id, attrs, store, iface="eth0", addr_fn=iface_ipv4,
                 addr_wait=8.0, peer_uid=proc_peer_uid):
        self.instance_id = instance_id
        self.attrs = dict(attrs)
        self.store = store
        self.iface = iface
        self.addr_fn = addr_fn
        self.addr_wait = addr_wait
        self.peer_uid = peer_uid

    def wait_ipv4(self):
        """eth0's address, polling up to addr_wait seconds for DHCP to land."""
        deadline = time.monotonic() + self.addr_wait
        while True:
            ip = self.addr_fn(self.iface)
            if ip is not None and usable_ipv4(ip):
                return ip
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(0.25, remaining))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "cogworx-pve-metadata"
    # Applied to the connection by StreamRequestHandler: a client that stalls
    # mid-request is dropped instead of holding a thread.
    timeout = 10

    def handle_one_request(self):
        # The stdlib dispatches to do_<METHOD> and answers anything else 501;
        # every request goes through _dispatch instead so that the method
        # refusal is the 405 the contract names, after the peer checks.
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if len(self.raw_requestline.split()) == 2:
                # HTTP/0.9 has no headers, so it can never carry Metadata-Flavor.
                # Answer nothing, before a parser that (on some Python versions)
                # would wait for headers that never come.
                self.close_connection = True
                return
            if not self.parse_request():
                return
            self.close_connection = True
            self._dispatch()
            self.wfile.flush()
        except (TimeoutError, ConnectionError):
            self.close_connection = True

    def version_string(self):
        return self.server_version

    def log_request(self, code="-", size="-"):
        pass

    def log_message(self, format, *args):
        LOG.debug("http: " + format, *args)

    def send_error(self, code, message=None, explain=None):
        # Reached only from the stdlib parser. Never echo the request back, and
        # always answer with a status line and headers, even to a request the
        # parser could not place in any HTTP version.
        if getattr(self, "request_version", "") == "HTTP/0.9":
            self.request_version = ""
        LOG.warning("refused %s: %s", code, message or "malformed request")
        self._reply(code, b"")

    def _reply(self, code, body, ctype="application/text"):
        if not body and code >= 400:
            body = (http.HTTPStatus(code).phrase + "\n").encode("ascii")
        self.send_response(code)
        self.send_header("Metadata-Flavor", "Google")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if getattr(self, "command", "") != "HEAD":
            self.wfile.write(body)

    def _refuse(self, code, why):
        LOG.warning("refused %d %s %r: %s", code, getattr(self, "command", ""), self.path[:160], why)
        self._reply(code, b"")

    def _dispatch(self):
        app = self.server.app
        uid = app.peer_uid(self.connection.getsockname(), self.client_address)
        if uid != 0:
            return self._refuse(403, "peer uid %s is not root" % ("unknown" if uid is None else uid))
        if "X-Forwarded-For" in self.headers:
            return self._refuse(403, "X-Forwarded-For present")
        if self.command not in ("GET", "PUT", "DELETE"):
            return self._refuse(405, "method not allowed")
        raw = self.path
        if "?" in raw or "%" in raw or ".." in raw:
            return self._refuse(400, "query string, escape or traversal in the target")
        if self.headers.get_all("Metadata-Flavor") != ["Google"]:
            return self._refuse(403, "missing Metadata-Flavor: Google")
        if "Transfer-Encoding" in self.headers:
            return self._refuse(400, "Transfer-Encoding is not supported")
        if not raw.startswith(PREFIX):
            return self._reply(404, b"")
        rest = raw[len(PREFIX):]

        m = _GA_PATH.fullmatch(rest)
        if m:
            return self._guest_attribute(app, m.group(1) + "/" + m.group(2))
        if self.command != "GET":
            if rest == "instance/id" or rest.startswith("instance/network-interfaces/") or _ATTR_PATH.fullmatch(rest):
                return self._refuse(405, "read-only path")
            return self._reply(404, b"")
        if not self._no_body():
            return None
        if rest == "instance/id":
            if app.instance_id is None:
                return self._refuse(503, "no instance id")
            return self._reply(200, app.instance_id.encode("ascii"))
        m = _ATTR_PATH.fullmatch(rest)
        if m:
            value = app.attrs.get(m.group(1))
            if value is None:
                return self._reply(404, b"")
            return self._reply(200, value.encode("utf-8"))
        if rest == "instance/network-interfaces/":
            if app.wait_ipv4() is None:
                return self._refuse(503, "%s has no usable IPv4 address" % app.iface)
            return self._reply(200, b"0/\n")
        if rest == "instance/network-interfaces/0/ip":
            ip = app.wait_ipv4()
            if ip is None:
                return self._refuse(503, "%s has no usable IPv4 address" % app.iface)
            return self._reply(200, ip.encode("ascii"))
        return self._reply(404, b"")

    def _content_length(self):
        """The declared body length; None (after a 400) when malformed."""
        values = self.headers.get_all("Content-Length") or []
        if len(values) > 1 or (values and not _CONTENT_LENGTH.fullmatch(values[0].strip())):
            self._refuse(400, "malformed Content-Length")
            return None
        return int(values[0]) if values else 0

    def _no_body(self):
        n = self._content_length()
        if n is None:
            return False
        if n:
            self._refuse(400, "unexpected request body")
            return False
        return True

    def _guest_attribute(self, app, key):
        if self.command == "GET":
            if not self._no_body():
                return None
            value = app.store.get(key)
            if value is None:
                return self._reply(404, b"")
            return self._reply(200, value.encode("utf-8"))
        if self.command == "DELETE":
            if not self._no_body():
                return None
            try:
                existed = app.store.delete(key)
            except OSError as e:
                LOG.error("guest attributes: DELETE %s not persisted (%s)", key, e)
                return self._reply(500, b"")
            if existed:
                LOG.info("guest attributes: deleted %s", key)
            return self._reply(200, b"")
        # PUT
        if "Content-Length" not in self.headers:
            return self._refuse(400, "PUT without Content-Length")
        n = self._content_length()
        if n is None:
            return None
        if n > GA_MAX_VALUE:
            return self._refuse(413, "value of %d bytes exceeds %d" % (n, GA_MAX_VALUE))
        body = self.rfile.read(n)
        if len(body) != n:
            return self._refuse(400, "short request body")
        try:
            value = body.decode("utf-8")
        except UnicodeDecodeError:
            return self._refuse(400, "value is not UTF-8")
        try:
            app.store.put(key, value)
        except LimitExceeded as e:
            return self._refuse(413, str(e))
        except OSError as e:
            LOG.error("guest attributes: PUT %s not persisted (%s)", key, e)
            return self._reply(500, b"")
        LOG.info("guest attributes: set %s (%d bytes)", key, n)
        return self._reply(200, b"")


class MetadataServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """An HTTP server over an ALREADY-LISTENING socket (systemd's, or --listen's)."""

    daemon_threads = True

    def __init__(self, sock, app):
        self.address_family = sock.family
        http.server.HTTPServer.__init__(self, sock.getsockname()[:2], Handler, bind_and_activate=False)
        self.socket.close()
        self.socket = sock
        self.app = app

    def handle_error(self, request, client_address):
        # The stdlib prints the traceback bare to stderr; keep it in our log.
        LOG.exception("unhandled error serving %s", client_address)


def systemd_socket():
    """The socket systemd passed as fd 3, or None when not socket-activated."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    fds = os.environ.get("LISTEN_FDS", "")
    for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(name, None)
    if fds != "1":
        raise SystemExit("cogworx-pve-metadata: expected exactly one socket from systemd, got LISTEN_FDS=%r" % fds)
    sock = socket.socket(fileno=3)
    sock.set_inheritable(False)
    if sock.type != socket.SOCK_STREAM or not sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
        raise SystemExit("cogworx-pve-metadata: fd 3 is not a listening stream socket")
    return sock


def listen_socket(spec):
    host, sep, port = spec.rpartition(":")
    if not sep or not host or not port.isdigit() or int(port) > 65535:
        raise SystemExit("cogworx-pve-metadata: --listen wants HOST:PORT, got %r" % spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, int(port)))
    sock.listen(64)
    return sock


def serve(args):
    sock = listen_socket(args.listen) if args.listen else systemd_socket()
    if sock is None:
        LOG.error("no socket: run under systemd socket activation or pass --listen HOST:PORT")
        return 2
    app = Metadata(
        instance_id=read_instance_id(args.dmi_uuid_path),
        attrs=read_boot_attrs(args.dmi_serial_path),
        store=GuestAttributeStore(args.state_dir, read_boot_id(), read_booted_system(args.booted_system_path)),
        iface=args.iface,
    )
    server = MetadataServer(sock, app)

    def stop(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    LOG.info("listening on %s:%d", *sock.getsockname()[:2])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def print_attr(args):
    """Decode DMI directly (no HTTP) and print one served attribute."""
    value = read_boot_attrs(args.dmi_serial_path).get(args.print_attr)
    if value is None:
        LOG.error("attribute %r is not set", args.print_attr[:128])
        return 1
    sys.stdout.write(value + "\n")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="cogworx-pve-metadata",
        description="Local GCE-metadata emulator for cogbox PVE hosts.",
    )
    p.add_argument("command", nargs="?", choices=["serve"], help="serve the metadata HTTP subset")
    p.add_argument("--print-attr", metavar="NAME", help="print one instance attribute decoded from DMI and exit (1 if absent)")
    p.add_argument("--listen", metavar="HOST:PORT", help="serve on this address instead of a socket-activated fd 3 (tests)")
    p.add_argument("--dmi-serial-path", default="/sys/class/dmi/id/product_serial")
    p.add_argument("--dmi-uuid-path", default="/sys/class/dmi/id/product_uuid")
    p.add_argument("--state-dir", default="/run/cogworx")
    p.add_argument("--booted-system-path", default="/run/booted-system",
                   help="the link whose target is reported as `sys` in the state file (read once at start)")
    p.add_argument("--iface", default="eth0")
    args = p.parse_args(argv)
    if (args.command == "serve") == (args.print_attr is not None):
        p.error("give exactly one of 'serve' or --print-attr NAME")
    if args.listen and args.command != "serve":
        p.error("--listen only applies to 'serve'")

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("cogworx-pve-metadata: %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    LOG.propagate = False

    if args.print_attr is not None:
        return print_attr(args)
    return serve(args)


if __name__ == "__main__":
    sys.exit(main())
