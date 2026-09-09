# Apple Silicon macOS

Cogbox's `aarch64-darwin` package runs the CLI, QEMU, and network helpers on
macOS. QEMU boots an `aarch64-linux` NixOS guest with Hypervisor.framework (HVF).
It does not need a Linux VM around the runtime, Docker, or nested virtualization.

Install Nix with flakes enabled. Building the NixOS guest requires an
`aarch64-linux` Nix builder for outputs unavailable from binary caches. A remote
Linux machine works, as does Nixpkgs' [Darwin Linux builder](https://nixos.org/manual/nixpkgs/unstable/#sec-darwin-builder).
That builder is used to build the guest; it can be stopped once the package has
been built. Guest extensions and plugins may require it again when rebuilding.

```sh
# After configuring an aarch64-linux builder:
nix build .#cogbox
./result/bin/cogbox

# Or run the flake directly:
nix run . -- --name work
```

New instances default to 4 vCPUs and 8192 MiB of RAM. `--vcpu` and `--mem`
override these values. Existing instance configuration retains its settings.
Configuration remains in `~/.config/cogbox` and data in `~/.local/share/cogbox`,
with the usual XDG overrides. Without `XDG_RUNTIME_DIR`, runtime sockets live in
`/tmp/cogbox-runtime-$UID`; a launch refuses symlinks and directories owned by
another user, allowing the invoking user's or root's directory under sudo.
macOS resolves symlinks such as `/tmp` to
`/private/tmp` when canonicalizing additional directory grants.

The VM uses the same 9p shares, read-only harness configuration, per-instance
overlays, SSH access, and fw_cfg credential staging as Linux. The macOS launcher's
default port forwards bind to loopback; `bindAddr` selects another address.

In `rules` and `full` mode, a separate `cogbox-slirp` process translates QEMU's
Ethernet frames using libslirp. In `rules` mode it loads `libnetfilter.dylib` via
dyld interposition, sharing the existing L4 rules, DNS rules, TCP remapping,
L7 proxies, and credential injection. It refuses to start if the filter or its
rules file is missing. The library is loaded only into the network helper.
`none` mode uses QEMU's restricted networking with the SSH/HTTP port forwards.

The lifetime lock uses macOS `flock`. Process identity comes from libproc rather
than `/proc`. Stop requests carry the launch nonce through a private FIFO; the
launcher handles its own request, avoiding a PID reuse race on a platform without
Linux pidfds. The existing child-first shutdown and outcome reporting apply.
The native shutdown helper sends QMP `system_powerdown` to the ARM machine's
GPIO power button; it does not require an emulated keyboard.

Linux container/GCE packages, nftables redirection, host UID switching, custom
passt DNS forwarding, and the hosted mosh UDP range are Linux-only. Their host
integration environment variables are rejected on a macOS launch.

For development, host tools and tests can be built without a Linux builder:

```sh
nix build .#cogbox-host-tools .#cogbox-slirp
nix build .#checks.aarch64-darwin.zig-tests
nix build .#checks.aarch64-darwin.native-runtime
```

`cogbox-host-tools` includes the packaged CLI and proxies for checks and
configuration management; it has no guest runner. Use `cogbox` to boot a VM.
The native runtime check exercises real TCP/UDP filtering and reload, framed
Ethernet transport, missing-filter refusal, file locking, and the launcher/stop
protocol with a temporary child process, including partial requests and a
force-stop during shutdown. It does not boot the NixOS guest.
