//go:build linux

// The `worker` mode: the splice-tier ECH gate through the real l7proxy worker.
//
// The Zig unit tests prove the gate piecewise (shape, probe, cache) because
// there is no worker-level harness in them, and `cogbox __ech-probe` bypasses
// the worker. This mode runs `cogbox __l7proxy` itself and sends ECH hellos
// through its SOCKS5 front door, exactly as the guest's shim does, to origins
// on documentation addresses. It asserts on the proxy's log lines and on what
// each origin received, so a gate that splices after a capable or unknown
// probe, probes the guest's SOCKS destination instead of the address it
// re-resolved and dialled, ignores the default-off switch, or serves a cached
// answer learned under another ALPN fails here.
//
// It needs a private user, network and mount namespace (checks.l7-ech-gate
// runs it under `unshare -rnm`): it puts the addresses below on lo and binds
// its own /etc/hosts over /etc, and refuses to start anywhere else.

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	gateProxyPort = 18101 // inside the private network namespace

	ipPlain  = "203.0.113.5" // TLS 1.3, no ECH keys
	ipECH    = "203.0.113.6" // ECH keys sent as retry configs, none under ALPN acme-tls/1 (echByALPN)
	ipTLS12  = "203.0.113.7" // TLS 1.2 only
	ipL4Deny = "203.0.113.9" // denied by the L4 rules; nothing listens

	plainName  = "plain.example.com"
	tls12Name  = "tls12.example.com"
	l4DenyName = "l4deny.example.com"
	// publicName (the ECH config's public_name, unlisted: L4 decides it) and
	// denied (l7-denied) both resolve to ipECH.
)

var gateHosts = strings.Join([]string{
	ipPlain + " " + plainName,
	ipECH + " " + publicName + " " + denied,
	ipTLS12 + " " + tls12Name,
	ipL4Deny + " " + l4DenyName,
}, "\n") + "\n"

const (
	gateL4Rules = "deny " + ipL4Deny + "/32\nallow 0.0.0.0/0\n"
	gateL7Rules = "mode passthrough\nallow " + plainName + "\nallow " + tls12Name + "\ndeny " + denied + "\n"
)

// isolate refuses to run outside a private user + network namespace, then
// puts the origin addresses on lo and binds a private /etc (hosts + a files-only
// nsswitch.conf) over /etc in this mount namespace.
func isolate(tmp string) error {
	m, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	if strings.Contains(string(m), "4294967295") {
		return errors.New("not in a private user namespace: run under unshare -rnm")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range ifs {
		if i.Name != "lo" {
			return fmt.Errorf("interface %s present: not in a private network namespace (run under unshare -rnm)", i.Name)
		}
	}
	ipCmds := [][]string{{"link", "set", "lo", "up"}}
	for _, a := range []string{ipPlain, ipECH, ipTLS12, ipL4Deny} {
		ipCmds = append(ipCmds, []string{"addr", "add", a + "/32", "dev", "lo"})
	}
	for _, args := range ipCmds {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	etc := filepath.Join(tmp, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return err
	}
	for _, f := range []string{"passwd", "group"} {
		if b, err := os.ReadFile("/etc/" + f); err == nil {
			if err := os.WriteFile(filepath.Join(etc, f), b, 0o644); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(etc, "hosts"), []byte(gateHosts), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(etc, "nsswitch.conf"), []byte("hosts: files\n"), 0o644); err != nil {
		return err
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %v", err)
	}
	if err := syscall.Mount(etc, "/etc", "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s over /etc: %v", etc, err)
	}
	// glibc asks nscd before nsswitch whenever its socket exists (a NixOS host
	// running this by hand), and nscd answers from the host's own /etc/hosts.
	if fi, err := os.Stat("/run/nscd"); err == nil && fi.IsDir() {
		if err := syscall.Mount("tmpfs", "/run/nscd", "tmpfs", 0, ""); err != nil {
			return fmt.Errorf("hide /run/nscd: %v", err)
		}
	}
	return nil
}

// origin counts every ClientHello that reaches it (GetConfigForClient runs
// once per hello, before any version check, so a hello it then refuses
// counts too; the proxy's dialled-but-unused upstream connection sends none)
// and every completed handshake that accepted ECH.
type origin struct {
	hellos atomic.Int64
	echOK  atomic.Int64
}

func serveOrigin(o *origin, addr string, cfg *tls.Config) error {
	cfg = cfg.Clone()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		o.hellos.Add(1)
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				tc := tls.Server(c, cfg)
				if tc.Handshake() != nil {
					return
				}
				st := tc.ConnectionState()
				if st.ECHAccepted {
					o.echOK.Add(1)
				}
				tc.Write([]byte("hello from " + st.ServerName + "\n"))
			}(c)
		}
	}()
	return nil
}

// gateProxy is one `cogbox __l7proxy` run, its stderr (the log) in a file.
type gateProxy struct {
	name string
	cmd  *exec.Cmd
	log  string
	mark int
}

// startGateProxy starts the proxy with HOME and XDG under `tmp` (never the
// caller's) plus `extra` env, and waits for its listening line.
func startGateProxy(cogbox, tmp, name string, extra ...string) (*gateProxy, error) {
	rt := filepath.Join(tmp, name)
	home := filepath.Join(rt, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(rt, "netfilter-rules"), []byte(gateL4Rules), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(rt, "l7-rules"), []byte(gateL7Rules), 0o644); err != nil {
		return nil, err
	}
	p := &gateProxy{name: name, log: filepath.Join(rt, "proxy.log")}
	lf, err := os.Create(p.log)
	if err != nil {
		return nil, err
	}
	defer lf.Close()
	p.cmd = exec.Command(cogbox, "__l7proxy", rt, fmt.Sprint(gateProxyPort))
	p.cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local/share"),
		"XDG_STATE_HOME=" + filepath.Join(home, ".local/state"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
	}, extra...)
	p.cmd.Stdout, p.cmd.Stderr = lf, lf
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	if _, ok := p.waitFor("l7proxy: listening on", 10*time.Second); !ok {
		p.stop()
		return nil, fmt.Errorf("%s: proxy never listened; log: %q", name, p.all())
	}
	return p, nil
}

func (p *gateProxy) all() string {
	b, _ := os.ReadFile(p.log)
	return string(b)
}

// begin marks the log; since returns what was logged after the mark.
func (p *gateProxy) begin()        { p.mark = len(p.all()) }
func (p *gateProxy) since() string { return p.all()[p.mark:] }

func (p *gateProxy) waitFor(sub string, d time.Duration) (string, bool) {
	for deadline := time.Now().Add(d); ; time.Sleep(20 * time.Millisecond) {
		if s := p.since(); strings.Contains(s, sub) || !time.Now().Before(deadline) {
			return s, strings.Contains(s, sub)
		}
	}
}

// stop kills the proxy and prints its log, the evidence behind every case.
func (p *gateProxy) stop() {
	p.cmd.Process.Kill()
	p.cmd.Wait()
	fmt.Printf("== proxy %s\n", p.name)
	for _, l := range strings.SplitAfter(p.all(), "\n") {
		if l != "" {
			fmt.Print("   ", l)
		}
	}
}

// socksDial opens a SOCKS5 CONNECT to dst:443 through the proxy, as the guest
// shim does.
func socksDial(dst string) (net.Conn, error) {
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", gateProxyPort))
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 5 || b[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks greeting: %v %x", err, b)
	}
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(dst).To4()...)
	req = binary.BigEndian.AppendUint16(req, 443)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	r := make([]byte, 10)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks connect: %v %x", err, r)
	}
	return c, nil
}

// craftedHello is a ClientHello with an SNI, an optional ALPN list and an ECH
// extension: "none", "stub" (the malformed 1-byte extension) or "grease" (a
// well-formed RFC 9849 outer extension, HKDF-SHA256 / AES-128-GCM, a random
// config_id, a random 32-byte enc and 160-byte payload: what Chromium sends,
// and the same suite and enc length as Go's real ECH client with this
// fixture's config). It offers no supported_versions, so an origin it is
// spliced to refuses it after counting it.
func craftedHello(sni, ech string, alpn ...string) []byte {
	var ext []byte
	entry := append([]byte{0}, u16(nil, len(sni))...)
	entry = append(entry, sni...)
	list := append(u16(nil, len(entry)), entry...)
	ext = u16(ext, 0x0000)
	ext = u16(ext, len(list))
	ext = append(ext, list...)
	if len(alpn) > 0 {
		var names []byte
		for _, a := range alpn {
			names = append(names, byte(len(a)))
			names = append(names, a...)
		}
		ext = u16(ext, 0x0010)
		ext = u16(ext, len(names)+2)
		ext = u16(ext, len(names))
		ext = append(ext, names...)
	}
	switch ech {
	case "stub":
		ext = u16(ext, 0xfe0d)
		ext = u16(ext, 1)
		ext = append(ext, 0)
	case "grease":
		rnd := make([]byte, 1+32+160)
		rand.Read(rnd)
		outer := []byte{0, 0, 1, 0, 1, rnd[0]}
		outer = u16(outer, 32)
		outer = append(outer, rnd[1:33]...)
		outer = u16(outer, 160)
		outer = append(outer, rnd[33:]...)
		ext = u16(ext, 0xfe0d)
		ext = u16(ext, len(outer))
		ext = append(ext, outer...)
	}
	body := append([]byte{3, 3}, make([]byte, 32)...) // legacy_version + random
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)    // empty session_id, one suite, null compression
	body = u16(body, len(ext))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(u16([]byte{0x16, 3, 1}, len(hs)), hs...)
}

// sendHello pushes a crafted hello to dst through the proxy and reads until
// the connection closes (the proxy refusing it, or the origin refusing the
// spliced hello).
func sendHello(dst, sni, ech string, alpn ...string) error {
	c, err := socksDial(dst)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write(craftedHello(sni, ech, alpn...)); err != nil {
		return err
	}
	io.Copy(io.Discard, c)
	return nil
}

// realECH runs Go's ECH client through the proxy to dst: inner name `inner`,
// outer name the config's public_name, ALPN `alpn`. It reports whether the
// handshake completed with ECH accepted, i.e. the inner name was reached.
func realECH(dst, inner, alpn string, configList []byte, pool *x509.CertPool) bool {
	c, err := socksDial(dst)
	if err != nil {
		return false
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{
		ServerName:                     inner,
		RootCAs:                        pool,
		NextProtos:                     []string{alpn},
		EncryptedClientHelloConfigList: configList,
		MinVersion:                     tls.VersionTLS13,
	})
	if tc.Handshake() != nil {
		return false
	}
	return tc.ConnectionState().ECHAccepted
}

type gateCheck struct{ fails []string }

func (g *gateCheck) failf(format string, a ...any) {
	g.fails = append(g.fails, fmt.Sprintf(format, a...))
}

// need waits for every `subs` in what `p` logged since its mark.
func (g *gateCheck) need(name string, p *gateProxy, subs ...string) {
	for _, s := range subs {
		if got, ok := p.waitFor(s, 5*time.Second); !ok {
			g.failf("%s: log lacks %q; got %q", name, s, got)
		}
	}
}

// absent settles briefly, then fails on any `subs` logged since the mark.
func (g *gateCheck) absent(name string, p *gateProxy, subs ...string) {
	time.Sleep(200 * time.Millisecond)
	got := p.since()
	for _, s := range subs {
		if strings.Contains(got, s) {
			g.failf("%s: log has %q; got %q", name, s, got)
		}
	}
}

// hellos checks that `o` received exactly `want` ClientHellos since `before`.
func (g *gateCheck) hellos(name string, o *origin, before, want int64) {
	time.Sleep(100 * time.Millisecond)
	if got := o.hellos.Load() - before; got != want {
		g.failf("%s: origin received %d ClientHellos, want %d", name, got, want)
	}
}

func (g *gateCheck) noECH(name string, o *origin, before int64, accepted bool) {
	if accepted || o.echOK.Load() != before {
		g.failf("%s: a real ECH hello reached its inner name %s through the splice", name, denied)
	}
}

func runWorker(cogbox string) error {
	tmp, err := os.MkdirTemp("", "ech-gate")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := isolate(tmp); err != nil {
		return err
	}

	cert, pool, err := selfSigned()
	if err != nil {
		return err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cfgBytes := echConfig(echConfID, priv.PublicKey().Bytes(), publicName)
	configList := append(u16(nil, len(cfgBytes)), cfgBytes...)
	keys := []tls.EncryptedClientHelloKey{{Config: cfgBytes, PrivateKey: priv.Bytes(), SendAsRetry: true}}
	base := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	var plain, ech, tls12 origin
	for _, o := range []struct {
		o    *origin
		addr string
		cfg  *tls.Config
	}{
		{&plain, ipPlain + ":443", base},
		{&ech, ipECH + ":443", echByALPN(base, keys)},
		{&tls12, ipTLS12 + ":443", &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12}},
	} {
		if err := serveOrigin(o.o, o.addr, o.cfg); err != nil {
			return err
		}
	}

	// Non-vacuity: dialled directly, the ECH origin really serves the denied
	// inner name to a real ECH client.
	dc, err := tls.Dial("tcp", ipECH+":443", &tls.Config{ServerName: denied, RootCAs: pool, NextProtos: []string{"h2"}, EncryptedClientHelloConfigList: configList, MinVersion: tls.VersionTLS13})
	if err != nil {
		return fmt.Errorf("non-vacuity: direct real ECH to the ECH origin: %v", err)
	}
	if st := dc.ConnectionState(); !st.ECHAccepted || st.ServerName != denied {
		dc.Close()
		return fmt.Errorf("non-vacuity: the ECH origin did not accept ECH for %s", denied)
	}
	dc.Close()

	g := &gateCheck{}
	send := func(name, dst, sni, ech string, alpn ...string) {
		if err := sendHello(dst, sni, ech, alpn...); err != nil {
			g.failf("%s: %v", name, err)
		}
	}
	probeLine := func(host, ip, result string) string {
		return "ech-probe host=" + host + " upstream=" + ip + ":443 result=" + result
	}
	reject := func(host, ip, outcome, detail, upstream string) string {
		return "reject host=" + host + " orig=" + ip + ":443 reason=ech-on-splice ech=" + outcome + " detail=" + detail + " upstream=" + upstream + " hint=\""
	}

	// --- probe on: every outcome through the worker ---
	p, err := startGateProxy(cogbox, tmp, "on", "COGBOX_L7_ECH_PROBE=1")
	if err != nil {
		return err
	}
	if !strings.Contains(p.all(), "ech_probe=on") {
		g.failf("on: startup line lacks ech_probe=on: %q", p.all())
	}

	// A GREASE hello to a server without ECH keys: probed not-capable, then
	// spliced (the origin gets the probe's hello and the guest's).
	p.begin()
	h := plain.hellos.Load()
	send("grease-not-capable", ipPlain, plainName, "grease")
	g.need("grease-not-capable", p, probeLine(plainName, ipPlain, "not-capable")+" detail=ee-without-ech")
	g.absent("grease-not-capable", p, "reject")
	g.hellos("grease-not-capable", &plain, h, 2)

	// The same again, with a fresh random config_id, enc and payload: a cache
	// hit, so no probe, and spliced.
	p.begin()
	h = plain.hellos.Load()
	send("grease-cached", ipPlain, plainName, "grease")
	g.absent("grease-cached", p, "ech-probe", "reject")
	g.hellos("grease-cached", &plain, h, 1)

	// The decoy-SNI hole itself: a real ECH hello, outer name public (unlisted,
	// L4-allowed), inner name denied. Probed capable and refused; the origin
	// sees only the probe.
	p.begin()
	h, e := ech.hellos.Load(), ech.echOK.Load()
	ok := realECH(ipECH, denied, "h2", configList, pool)
	g.need("real-ech-capable", p, probeLine(publicName, ipECH, "capable")+" detail=retry-configs", reject(publicName, ipECH, "capable", "retry-configs", ipECH+":443"))
	g.hellos("real-ech-capable", &ech, h, 1)
	g.noECH("real-ech-capable", &ech, e, ok)

	// Again: refused from the cache, nothing reaches the origin.
	p.begin()
	h, e = ech.hellos.Load(), ech.echOK.Load()
	ok = realECH(ipECH, denied, "h2", configList, pool)
	g.need("real-ech-cached", p, reject(publicName, ipECH, "capable", "retry-configs", ipECH+":443"))
	g.absent("real-ech-cached", p, "ech-probe")
	g.hellos("real-ech-cached", &ech, h, 0)
	g.noECH("real-ech-cached", &ech, e, ok)

	// A TLS 1.2 server: unknown, refused, only the probe arrives.
	p.begin()
	h = tls12.hellos.Load()
	send("grease-tls12", ipTLS12, tls12Name, "grease")
	g.need("grease-tls12", p, probeLine(tls12Name, ipTLS12, "unknown"), "reason=ech-on-splice ech=unknown")
	g.hellos("grease-tls12", &tls12, h, 1)

	// An l7-denied name is refused for that, before any probe.
	p.begin()
	h = ech.hellos.Load()
	send("grease-l7-deny", ipECH, denied, "grease")
	g.need("grease-l7-deny", p, "reason=l7-deny")
	g.absent("grease-l7-deny", p, "ech-probe", "ech-on-splice")
	g.hellos("grease-l7-deny", &ech, h, 0)

	// A malformed ECH extension: refused before any dial or probe.
	p.begin()
	h = plain.hellos.Load()
	send("stub", ipPlain, plainName, "stub")
	g.need("stub", p, reject(plainName, ipPlain, "unknown", "ech-malformed", "-"))
	g.absent("stub", p, "ech-probe")
	g.hellos("stub", &plain, h, 0)

	// An L4-denied address: no vetted upstream, so no probe.
	p.begin()
	send("grease-l4-deny", ipL4Deny, l4DenyName, "grease")
	g.need("grease-l4-deny", p, "reason=no-vetted-upstream")
	g.absent("grease-l4-deny", p, "ech-probe", "ech-on-splice")

	// Steering: the guest picks the SOCKS destination, but the probe must go
	// to the address the proxy re-resolved and connected to. A real ECH hello
	// CONNECTed to the server without ECH keys, outer name publicName (which
	// resolves to the ECH origin, cached capable above): refused from that
	// cached answer. Nothing reaches either origin, so no probe went to the
	// SOCKS destination, which would have read not-capable.
	p.begin()
	hp := plain.hellos.Load()
	h, e = ech.hellos.Load(), ech.echOK.Load()
	ok = realECH(ipPlain, denied, "h2", configList, pool)
	g.need("steer", p, reject(publicName, ipPlain, "capable", "retry-configs", ipECH+":443"))
	g.hellos("steer", &plain, hp, 0)
	g.hellos("steer", &ech, h, 0)
	g.noECH("steer", &ech, e, ok)

	// No ECH at all: never gated, spliced.
	p.begin()
	h = ech.hellos.Load()
	send("no-ech", ipECH, publicName, "none")
	g.absent("no-ech", p, "ech-probe", "reject")
	g.hellos("no-ech", &ech, h, 1)
	p.stop()

	// --- the cache keys on ALPN ---
	// A fresh proxy: a GREASE hello under ALPN acme-tls/1, for which the ECH
	// origin holds no keys, is probed not-capable and spliced. A real ECH
	// hello under h2 to the same address and name, with the same ECH suite
	// and enc length, must get a probe of its own (capable) and be refused,
	// not that cached answer.
	p, err = startGateProxy(cogbox, tmp, "alpn", "COGBOX_L7_ECH_PROBE=1")
	if err != nil {
		return err
	}
	p.begin()
	h = ech.hellos.Load()
	send("grease-acme", ipECH, publicName, "grease", "acme-tls/1")
	g.need("grease-acme", p, probeLine(publicName, ipECH, "not-capable"))
	g.absent("grease-acme", p, "reject")
	g.hellos("grease-acme", &ech, h, 2)
	p.begin()
	h, e = ech.hellos.Load(), ech.echOK.Load()
	ok = realECH(ipECH, denied, "h2", configList, pool)
	g.need("real-ech-after-acme", p, probeLine(publicName, ipECH, "capable"), reject(publicName, ipECH, "capable", "retry-configs", ipECH+":443"))
	g.hellos("real-ech-after-acme", &ech, h, 1)
	g.noECH("real-ech-after-acme", &ech, e, ok)
	p.stop()

	// --- the default: probe off ---
	p, err = startGateProxy(cogbox, tmp, "default")
	if err != nil {
		return err
	}
	if !strings.Contains(p.all(), "ech_probe=off") {
		g.failf("default: startup line lacks ech_probe=off: %q", p.all())
	}
	p.begin()
	h = plain.hellos.Load()
	send("default-grease", ipPlain, plainName, "grease")
	g.need("default-grease", p, reject(plainName, ipPlain, "unknown", "disabled", "-"))
	g.absent("default-grease", p, "ech-probe")
	g.hellos("default-grease", &plain, h, 0)
	p.begin()
	h, e = ech.hellos.Load(), ech.echOK.Load()
	ok = realECH(ipECH, denied, "h2", configList, pool)
	g.need("default-real-ech", p, reject(publicName, ipECH, "unknown", "disabled", "-"))
	g.hellos("default-real-ech", &ech, h, 0)
	g.noECH("default-real-ech", &ech, e, ok)
	p.stop()

	// --- the switch fails closed: an unrecognised value is off, and says so;
	// the on spellings are case-insensitive ---
	for _, v := range []struct {
		val, state string
		warn       bool
	}{{"yes", "off", true}, {"0", "off", false}, {"TRUE", "on", false}, {"On", "on", false}} {
		name := "switch-" + v.val
		p, err = startGateProxy(cogbox, tmp, name, "COGBOX_L7_ECH_PROBE="+v.val)
		if err != nil {
			return err
		}
		log := p.all()
		if !strings.Contains(log, "ech_probe="+v.state) {
			g.failf("%s: startup line lacks ech_probe=%s: %q", name, v.state, log)
		}
		if warned := strings.Contains(log, "COGBOX_L7_ECH_PROBE='"+v.val+"'"); warned != v.warn {
			g.failf("%s: warning logged=%v, want %v: %q", name, warned, v.warn, log)
		}
		if v.state == "off" {
			p.begin()
			send(name, ipPlain, plainName, "grease")
			g.need(name, p, reject(plainName, ipPlain, "unknown", "disabled", "-"))
		}
		p.stop()
	}

	for _, f := range g.fails {
		fmt.Fprintln(os.Stderr, "  "+f)
	}
	if len(g.fails) > 0 {
		return fmt.Errorf("%d ECH gate expectation(s) failed", len(g.fails))
	}
	fmt.Println("ech gate: every case passed")
	return nil
}
