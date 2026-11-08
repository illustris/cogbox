# Browser defaults that turn Encrypted ClientHello (ECH) off, GREASE included.
# Imported by cogboxModules for every target (VM, hosted, container), and
# guarded by checks.guest-browser-ech-off.
#
# Why: the host-side l7proxy refuses a ClientHello that carries an ECH
# extension for every host it splices rather than terminates (unlisted hosts,
# --passthrough, `l7 mode passthrough`, the harness API hosts; logged
# `ech-on-splice`). Its ECH-capability probe, which lets ECH through to a
# server that does not take it (servers behind Cloudflare always do), is off
# unless the operator sets COGBOX_L7_ECH_PROBE=1. The splice routes on
# the cleartext outer SNI, and a real ECH hello can name an allowed outer host
# while the encrypted inner one is denied. Chromium-family browsers and Firefox
# send a GREASE ECH extension on every TLS 1.3 handshake, so without these
# files a guest browser fails with a bare ERR_CONNECTION_CLOSED on every
# refused HTTPS host that curl reaches.
#
# Who reads what (the policy directory is compiled into each build):
# - /etc/chromium/policies/managed: nixpkgs chromium.
# - /etc/opt/chrome/policies/managed: Google Chrome, which is also Playwright
#   MCP's default channel 'chrome'.
# - /etc/opt/chrome_for_testing/policies/managed: Chrome for Testing, i.e.
#   Playwright's channel 'chromium' and its headed chromium (npx playwright
#   install builds).
# - /etc/firefox/defaults/pref: nixpkgs Firefox and Playwright's Firefox.
# EncryptedClientHelloEnabled=false selects EchMode::kDisabled, so no GREASE is
# sent; --disable-features=EncryptedClientHello is a no-op in current Chromium
# (the feature was removed). Firefox GREASEs because
# security.tls.ech.grease_probability defaults to 100; its
# DisableEncryptedClientHello enterprise policy only locks
# network.dns.echconfig.* and does NOT stop GREASE, hence a defaults/pref file
# rather than policies.json.
#
# Not covered: chrome-headless-shell, Playwright's DEFAULT headless browser,
# has no policy loader and always sends GREASE ECH; nothing in the guest can
# reach it. Launch Playwright with channel 'chromium' (or 'chrome') instead,
# or list the host under allowed hosts so it is terminated.
#
# Precedence: Chromium merges every file in managed/ and the lexicographically
# LAST file wins a key conflict. cogbox-ech.json sorts before default.json and
# extra.json (what nixpkgs programs.chromium writes), so a plugin that sets the
# key explicitly wins. programs.chromium is not used here: it never writes
# opt/chrome_for_testing and it owns those two names.
#
# This is a compatibility default, not a security control: the guest is root
# and can remove these files, and non-browser clients can still send ECH. The
# host-side refusal stays authoritative.
{ lib, ... }: let
	echOff = builtins.toJSON { EncryptedClientHelloEnabled = false; };
in {
	environment.etc = {
		"chromium/policies/managed/cogbox-ech.json".text = echOff;
		"opt/chrome/policies/managed/cogbox-ech.json".text = echOff;
		"opt/chrome_for_testing/policies/managed/cogbox-ech.json".text = echOff;
		# One pref per line, built from a list: an indented string would keep
		# this file's tab indentation (Nix strips only leading spaces).
		"firefox/defaults/pref/cogbox-ech.js".text = lib.concatMapStrings (l: "${l}\n") [
			''pref("security.tls.ech.grease_probability", 0);''
			''pref("network.dns.echconfig.enabled", false);''
			''pref("network.dns.http3_echconfig.enabled", false);''
		];
	};
}
