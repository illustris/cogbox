package host

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type environment struct {
	Version  int    `json:"version"`
	Mode     string `json:"mode"`
	Instance string `json:"instance"`
}
type credential struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
	Secret  string `json:"secret"`
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func localOwner(p roots, name string, adopt bool) error {
	if os.Getenv("COGBOX_ENVIRONMENT") == "cogworx" {
		return errors.New("this host launch is managed by cogworx")
	}
	path := filepath.Join(p.configDir(name), "environment.json")
	var env environment
	err := readJSON(path, &env, false)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot read host environment ownership: %w", err)
	}
	if err == nil && (env.Version != 1 || env.Instance != name) {
		return errors.New("invalid host environment ownership")
	}
	if env.Mode == "cogworx" {
		return errors.New("instance is managed by cogworx; open its App view instead")
	}
	if env.Mode == "local" {
		return nil
	}
	if env.Mode != "" && env.Mode != "unknown" {
		return errors.New("unrecognized host environment mode")
	}
	if !adopt {
		return errors.New("instance ownership is unknown; use --adopt-local only for an instance you own locally")
	}
	// Validate adoption here; commit it only after the guest accepted our own
	// credential. A foreign credential refusal must leave unknown unchanged.
	return nil
}

func loadCredential(p roots, name string) (string, error) {
	dir := filepath.Join(p.configDir(name), "app")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "relay.json")
	var c credential
	err := readJSON(path, &c, true)
	if err == nil {
		b, decodeErr := hex.DecodeString(c.Secret)
		if c.Version != 1 || c.Owner != "local" || decodeErr != nil || len(b) != 32 {
			return "", errors.New("invalid or unowned host relay credential")
		}
		return c.Secret, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	secret, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := writeJSON(path, credential{1, "local", secret}); err != nil {
		return "", err
	}
	return secret, nil
}

// This script is constant: the secret travels on stdin, never in argv, shell
// expansion in the caller, environment, or logs. All guest writes occur as
// root; the host config remains the authority even if guest files are changed.
const generationGuard = `set -eu
IFS= read -r expected_launch
check_launch() {
  [ -f /var/lib/cogbox/.app-launch ] && [ ! -L /var/lib/cogbox/.app-launch ] || exit 26
  [ "$(cat /var/lib/cogbox/.app-launch)" = "$expected_launch" ] || exit 26
}
check_launch
`

const provisionScript = `set -eu
IFS= read -r secret
case "$secret" in *[!0-9a-f]*|'') exit 20;; esac
[ "${#secret}" = 64 ] || exit 20
dir=/var/lib/cogbox
[ -d "$dir" ] && [ ! -L "$dir" ] || exit 21
[ ! -e /var/lib/cogbox/claude-oauth.bound ] && [ ! -L /var/lib/cogbox/claude-oauth.bound ] || exit 24
[ ! -e /var/lib/cogbox-state/claude-oauth.bound ] && [ ! -L /var/lib/cogbox-state/claude-oauth.bound ] || exit 24
if [ -f /run/cogbox/environment.json ] && grep -Eq '"mode"[[:space:]]*:[[:space:]]*"cogworx"' /run/cogbox/environment.json; then exit 24; fi
[ "$(systemctl show -p LoadState --value cogbox-app-relay.service)" = loaded ] || exit 22
path="$dir/app-relay.env"
[ ! -L "$path" ] || exit 23
if [ -e "$path" ]; then
  [ -f "$path" ] || exit 23
  IFS= read -r owner < "$path"
  [ "$owner" = '# cogbox-local-app-relay-v1' ] || exit 23
  expected=$(printf '# cogbox-local-app-relay-v1\nCOGBOX_APP_RELAY_SECRET=%s' "$secret")
  [ "$(cat "$path")" = "$expected" ] || exit 23
fi
umask 077
check_launch
tmp=$(mktemp "$dir/.app-relay.XXXXXX")
trap 'rm -f "$tmp"' EXIT
printf '# cogbox-local-app-relay-v1\nCOGBOX_APP_RELAY_SECRET=%s\n' "$secret" > "$tmp"
chmod 600 "$tmp"
# Guest root already owns mktemp's file. A redundant chown fails on local 9p
# even for 0:0 -> 0:0; verify the guest ownership instead of changing it.
[ "$(stat -c '%u:%g' "$tmp")" = '0:0' ] || exit 25
changed=1
if [ -f "$path" ] && cmp -s "$tmp" "$path"; then changed=0; fi
# Replace even byte-identical content to repair permissions without restarting
# a healthy relay and disrupting its WebSockets.
check_launch
mv -f "$tmp" "$path"
if [ "$changed" = 1 ] || ! systemctl is-active --quiet cogbox-app-relay.service; then
  systemctl restart cogbox-app-relay.service
fi
`

type sshTarget struct {
	args       []string
	knownHosts string
}

func sshSnapshot(p roots, name, launch string) (sshTarget, error) {
	if !live(p, name, launch) {
		return sshTarget{}, errors.New("instance restarted before SSH endpoint snapshot")
	}
	b, err := readFile(filepath.Join(p.runtimeDir(name), "ssh-endpoint"), false)
	if err != nil {
		return sshTarget{}, errors.New("missing live SSH endpoint; restart the instance")
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return sshTarget{}, errors.New("malformed live SSH endpoint")
	}
	port, err := strconv.Atoi(f[0])
	if err != nil || port < 1 || port > 65535 {
		return sshTarget{}, errors.New("invalid live SSH port")
	}
	host := f[1]
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host != "127.0.0.1" && host != "::1" {
		return sshTarget{}, errors.New("local provisioning requires a loopback SSH endpoint")
	}
	key := filepath.Join(p.data, "cogbox_ed25519")
	if _, err := readFile(key, true); err != nil {
		return sshTarget{}, errors.New("local relay provisioning requires the cogbox SSH key; enable automatic keys or configure the relay manually")
	}
	pub, err := readFile(filepath.Join(p.data, "instances", name, "ssh", "ssh_host_ed25519_key.pub"), false)
	if err != nil {
		return sshTarget{}, errors.New("guest SSH host key is not ready; wait for boot or restart the instance, then retry")
	}
	publicKey, err := parseHostKey(string(pub))
	if err != nil {
		return sshTarget{}, err
	}
	if !live(p, name, launch) {
		return sshTarget{}, errors.New("instance restarted during SSH endpoint snapshot")
	}
	dir := filepath.Join(p.configDir(name), "app")
	if err := privateDir(dir); err != nil {
		return sshTarget{}, err
	}
	fh, err := os.CreateTemp(dir, ".known-hosts-")
	if err != nil {
		return sshTarget{}, err
	}
	if _, err := fmt.Fprintln(fh, "cogbox-app-target "+publicKey); err != nil {
		fh.Close()
		os.Remove(fh.Name())
		return sshTarget{}, err
	}
	if err := fh.Close(); err != nil {
		os.Remove(fh.Name())
		return sshTarget{}, err
	}
	return sshTarget{[]string{"-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + fh.Name(), "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlias=cogbox-app-target", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UpdateHostKeys=no", "-o", "VerifyHostKeyDNS=no", "-o", "LogLevel=ERROR", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", key, "-p", strconv.Itoa(port), "root@" + host}, fh.Name()}, nil
}

func parseHostKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	f := strings.Fields(s)
	if strings.ContainsAny(s, "\r\n") || len(f) < 2 || f[0] != "ssh-ed25519" {
		return "", errors.New("invalid guest SSH host public key")
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) != 51 || binary.BigEndian.Uint32(b[:4]) != 11 || string(b[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(b[15:19]) != 32 {
		return "", errors.New("invalid guest SSH host public key")
	}
	return f[0] + " " + f[1], nil
}

func guestCommand(ctx context.Context, p roots, name, launch string, sshArgs []string, script, input string) error {
	if !live(p, name, launch) {
		return errors.New("instance restarted before guest command")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := append(append([]string{}, sshArgs...), "sh -c '"+strings.ReplaceAll(generationGuard+script, "'", "'\\''")+"'")
	cmd := exec.CommandContext(cctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(launch + "\n" + input)
	// Guest output is untrusted and may contain credentials. Report fixed errors.
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			switch ee.ExitCode() {
			case 22:
				return errors.New("guest app relay is unavailable; update the instance's cogbox pin and restart")
			case 23:
				return errors.New("refusing to overwrite a foreign or unsafe guest relay credential")
			case 24:
				return errors.New("guest has cogworx-managed state; refusing local provisioning")
			case 25:
				return errors.New("guest shared state could not create a root-owned relay credential")
			case 26:
				return errors.New("guest launch identity is missing or changed; restart with current cogbox, then retry")
			}
		}
		return errors.New("could not provision the local guest relay over SSH; check the instance and SSH key, then retry")
	}
	if !live(p, name, launch) {
		return errors.New("instance restarted during guest command")
	}
	return nil
}

func relayAddress(ep endpoint) string { return net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)) }

func checkRelay(ctx context.Context, ep endpoint, secret string, isLive func() bool) error {
	// Selecting the relay's reserved self-port authenticates without sending any
	// request to an application. A tagged 400 proves that auth reached port validation.
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return fencedDial(ctx, network, addr, dialer.DialContext, isLive)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+relayAddress(ep)+"/_relay/"+secret+"/port/8080/", nil)
	res, err := client.Do(req)
	if err != nil {
		return errors.New("guest relay is unreachable; update the instance's cogbox pin and restart, then retry")
	}
	defer res.Body.Close()
	if res.StatusCode != 400 || res.Header.Get("X-Cogbox-Relay") != "1" {
		return errors.New("guest relay did not accept the local credential; retry provisioning or check guest relay logs")
	}
	return nil
}
