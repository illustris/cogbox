# cogworx-pve-upgrade as ONE executable file whose shebang is its own first
# line, `python3 -I`, and nothing else: the kernel then passes the INVOKED,
# unresolved path as sys.argv[0], and the tool's argv[0] rule tells two system
# generations apart by that path alone (their tool packages may be the same
# store path). So no makeWrapper and no writeShellScriptBin wrapper, ever.
#
# The source carries three placeholders: the child PATH (nix-env, nix-store,
# systemd-run, systemctl come from it, never from the caller's PATH) and the
# headroom floor and reserve in bytes. The check phase refuses any placeholder
# left over and any source that no longer parses.
{
	lib,
	writeTextFile,
	python3,
	nix,
	systemd,
	coreutils,
	util-linux,
	minFreeBytes,
	reserveBytes,
}:
let
	source = builtins.readFile ./cogworx_pve_upgrade.py;
	text = lib.replaceStrings
		[ "@childPath@" "@minFreeBytes@" "@reserveBytes@" ]
		[ (lib.makeBinPath [ nix systemd coreutils util-linux ]) (toString minFreeBytes) (toString reserveBytes) ]
		source;
in
writeTextFile {
	name = "cogworx-pve-upgrade";
	executable = true;
	destination = "/bin/cogworx-pve-upgrade";
	text = "#!${python3}/bin/python3 -I\n" + text;
	checkPhase = ''
		if grep -Eq '@[A-Za-z]+@' "$target"; then
			echo "cogworx-pve-upgrade: unsubstituted placeholder(s):" >&2
			grep -En '@[A-Za-z]+@' "$target" >&2
			exit 1
		fi
		${python3}/bin/python3 -I -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$target"
	'';
}
