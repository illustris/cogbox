"""Normalize a PVE system generation's compat doc at build time.

Usage: python3 -I compat_doc.py RAW.json > cogworx-pve-compat.json

RAW.json is builtins.toJSON of the evaluated values (pve/upgrade/module.nix).
The output is what the system's toplevel carries as cogworx-pve-compat.json
and what both cogworx-pve-upgrade (the guest compat rules) and cogworxd read:

  - controlCAKeys: each line reduced to `<type> <base64 blob>` (the comment
    dropped), sorted, unique. A blob that does not base64-decode, or whose
    wire form does not start with its own type string, FAILS THE BUILD with a
    message naming the line;
  - controlCAFingerprints: `SHA256:<unpadded base64 of sha256(blob)>` per key,
    in the same order (what `ssh-keygen -lf -E sha256` prints);
  - controlPlaneCIDRs, substituters, trustedPublicKeys, specialisations:
    sorted, unique. An http(s) substituter loses its trailing slashes first,
    as nix's own HTTP binary cache store does, so `https://cache.example/`
    and `https://cache.example` are one entry; other URLs stay verbatim;
  - release: null, or exactly {id, builtAt} in the option's grammar;
  - every key of schema 1 (RAW_KEYS) present: a missing one FAILS THE BUILD
    rather than defaulting, since an empty list where a value was expected
    (substituters, say) would fail cogworxd's rules on every target;
  - ASCII JSON with sorted keys, at most 16384 bytes (the readers' cap).

Stdlib only.
"""

import base64
import binascii
import hashlib
import json
import re
import sys

MAX_BYTES = 16384
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
BUILT_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
KEY_TYPE = re.compile(r"(ssh|ecdsa|sk)-[A-Za-z0-9@._+-]{1,64}")
SORTED_LISTS = ("controlPlaneCIDRs", "substituters", "trustedPublicKeys", "specialisations")
# Schema 1 as module.nix writes it; the output adds controlCAFingerprints.
RAW_KEYS = ("bootConfigVersions", "bootProof", "bootloader", "controlCAKeys", "controlPlaneCIDRs", "controlUser",
            "guestAttrsVersion", "guestDevice", "hostKeyPath", "interface", "kind", "release", "schema",
            "smbiosSelector", "specialisations", "stateDevice", "stateFormat", "substituters", "toolProto",
            "trustedPublicKeys", "txnSchema")
HTTP_URL = re.compile(r"https?://[^/]+(/.*)?")


class DocError(Exception):
    pass


def normalize_key(line):
    """`<type> <blob> [comment]` -> (`<type> <blob>`, fingerprint)."""
    fields = line.split()
    if len(fields) < 2 or not KEY_TYPE.fullmatch(fields[0]):
        raise DocError("controlCAKeys line is not '<type> <base64 blob> [comment]': %r" % line)
    ktype, blob = fields[0], fields[1]
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        raise DocError("controlCAKeys blob does not base64-decode: %r" % line)
    n = int.from_bytes(raw[:4], "big") if len(raw) >= 4 else -1
    if n < 0 or raw[4:4 + n] != ktype.encode("ascii"):
        raise DocError("controlCAKeys blob is not a %s key: %r" % (ktype, line))
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return ktype + " " + blob, fp


def normalize_substituter(url):
    """nix's HttpBinaryCacheStore drops a URL's trailing slashes; the other
    store types are left as configured."""
    if HTTP_URL.fullmatch(url):
        stripped = url.rstrip("/")
        if HTTP_URL.fullmatch(stripped):
            return stripped
    return url


def normalize(raw):
    if not isinstance(raw, dict):
        raise DocError("the raw compat doc is not an object")
    missing = [k for k in RAW_KEYS if k not in raw]
    if missing:
        raise DocError("the raw compat doc lacks %s" % ", ".join(missing))
    doc = dict(raw)
    lines = raw["controlCAKeys"]
    if not isinstance(lines, list) or not all(isinstance(l, str) for l in lines):
        raise DocError("controlCAKeys is not a list of strings")
    keys = {}
    for line in lines:
        key, fp = normalize_key(line)
        keys[key] = fp
    order = sorted(keys)
    doc["controlCAKeys"] = order
    doc["controlCAFingerprints"] = [keys[k] for k in order]
    for name in SORTED_LISTS:
        v = raw[name]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise DocError("%s is not a list of strings" % name)
        if name == "substituters":
            v = [normalize_substituter(x) for x in v]
        doc[name] = sorted(set(v))
    rel = raw.get("release")
    if rel is not None:
        if (not isinstance(rel, dict) or set(rel) != {"id", "builtAt"}
                or not isinstance(rel["id"], str) or not RELEASE_ID.fullmatch(rel["id"])
                or not isinstance(rel["builtAt"], str) or not BUILT_AT.fullmatch(rel["builtAt"])):
            raise DocError("release must be null or {id, builtAt} in the option's grammar: %r" % (rel,))
    out = json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    if len(out) > MAX_BYTES:
        raise DocError("the compat doc is %d bytes, over the %d-byte cap" % (len(out), MAX_BYTES))
    return out


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: compat_doc.py RAW.json\n")
        return 2
    try:
        with open(argv[1], "rb") as f:
            raw = json.loads(f.read())
        out = normalize(raw)
    except (OSError, ValueError, DocError) as e:
        sys.stderr.write("compat_doc.py: %s\n" % e)
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
