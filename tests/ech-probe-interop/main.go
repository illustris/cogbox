// ech-probe-interop drives `cogbox __ech-probe` (the l7proxy's ECH-capability
// probe, zig/src/l7proxy/echprobe.zig) against real Go crypto/tls servers, with
// and without EncryptedClientHelloKeys, an OpenSSL s_server, plus two raw TCP
// misbehavers.
//
// The Zig unit tests build their fake server from the probe's own key
// schedule, so only a real TLS stack proves that the handshake (ServerHello,
// the handshake traffic keys, the record layer) and the reading of
// retry_configs out of EncryptedExtensions are right. checks.l7-ech-probe-interop
// runs this.
//
// The `worker` mode (worker.go, checks.l7-ech-gate) instead drives the real
// l7proxy worker, `cogbox __l7proxy`, with ECH hellos through its SOCKS5 front
// door: the gate's wiring, which neither the unit tests nor `__ech-probe`
// reach.
//
// Usage:
//
//	ech-probe-interop <path-to-cogbox>
//	ech-probe-interop worker <path-to-cogbox>   (under unshare -rnm only)
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	publicName = "public.example.com"
	allowed    = "allowed.example.com"
	denied     = "denied.example.com"
	echConfID  = 7
)

func u16(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }

// echConfig marshals one ECHConfig (RFC 9849 section 4): version 0xfe0d,
// DHKEM(X25519, HKDF-SHA256), one suite HKDF-SHA256 / AES-128-GCM.
func echConfig(id uint8, pub []byte, name string) []byte {
	var c []byte
	c = append(c, id)
	c = u16(c, 0x0020)
	c = u16(c, len(pub))
	c = append(c, pub...)
	c = u16(c, 4)
	c = u16(c, 0x0001)
	c = u16(c, 0x0001)
	c = append(c, 0) // maximum_name_length
	c = append(c, byte(len(name)))
	c = append(c, name...)
	c = u16(c, 0) // no extensions
	out := u16(nil, 0xfe0d)
	out = u16(out, len(c))
	return append(out, c...)
}

// echByALPN is `base` with ECH keys chosen per ClientHello by ALPN (Go's
// Config.GetEncryptedClientHelloKeys): none for a hello offering acme-tls/1 (a
// TLS-ALPN-01 responder path, say), `keys` for every other. Such a server
// follows RFC 9849 section 7.1 for every single hello, yet answers the probe
// capable or not by the ALPN it carries -- which is why the probe copies the
// guest's ALPN and the gate's cache keys on it.
func echByALPN(base *tls.Config, keys []tls.EncryptedClientHelloKey) *tls.Config {
	c := base.Clone()
	c.NextProtos = []string{"h2", "acme-tls/1"}
	c.GetEncryptedClientHelloKeys = func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		if slices.Contains(chi.SupportedProtos, "acme-tls/1") {
			return nil, nil
		}
		return keys, nil
	}
	return c
}

func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ech-probe-interop"},
		DNSNames:              []string{publicName, allowed, denied},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, pool, nil
}

// pemPair encodes a selfSigned certificate and its key for openssl.
func pemPair(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, nil
}

// serveTLS runs handshakes in goroutines; the probe aborts every one of them
// after EncryptedExtensions, so handshake errors are expected and ignored.
func serveTLS(cfg *tls.Config) (string, error) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		return "", err
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
				if c.(*tls.Conn).Handshake() == nil {
					c.Write([]byte("ok\n"))
				}
			}(c)
		}
	}()
	return ln.Addr().String(), nil
}

// serveRaw accepts plain TCP and hands each connection to fn.
func serveRaw(fn func(net.Conn)) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(c)
		}
	}()
	return ln.Addr().String(), nil
}

// serveOpenSSL starts `openssl s_server` (from PATH) on a loopback port with
// `cert`, TLS 1.3 only and ALPN h2, and returns its address and the process.
// s_server handles one connection at a time and keeps accepting after a
// failed handshake, which is all the probe needs.
func serveOpenSSL(cert tls.Certificate, dir string) (string, *exec.Cmd, error) {
	certPEM, keyPEM, err := pemPair(cert)
	if err != nil {
		return "", nil, err
	}
	cp, kp := filepath.Join(dir, "ossl-cert.pem"), filepath.Join(dir, "ossl-key.pem")
	if err := os.WriteFile(cp, certPEM, 0o600); err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(kp, keyPEM, 0o600); err != nil {
		return "", nil, err
	}
	// A free port: bind :0, read it, release it for s_server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()
	ln.Close()
	cmd := exec.Command("openssl", "s_server", "-accept", addr, "-cert", cp, "-key", kp, "-tls1_3", "-alpn", "h2", "-quiet")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return "", nil, fmt.Errorf("openssl s_server (needs openssl on PATH): %v", err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return addr, cmd, nil
		}
	}
	cmd.Process.Kill()
	cmd.Wait()
	return "", nil, fmt.Errorf("openssl s_server never listened on %s", addr)
}

type probeCase struct {
	name    string
	addr    string
	sni     string
	alpn    string
	result  string
	details []string // any of these; empty = any detail
	maxWall time.Duration
}

func runProbe(cogbox string, pc probeCase) (result, detail, line string, wall time.Duration, err error) {
	host, port, err := net.SplitHostPort(pc.addr)
	if err != nil {
		return "", "", "", 0, err
	}
	args := []string{"__ech-probe", host, port, pc.sni}
	if pc.alpn != "" {
		args = append(args, pc.alpn)
	}
	start := time.Now()
	out, err := exec.Command(cogbox, args...).Output()
	wall = time.Since(start)
	line = strings.TrimSpace(string(out))
	if err != nil {
		return "", "", line, wall, fmt.Errorf("cogbox %s: %v", strings.Join(args, " "), err)
	}
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, "result="); ok {
			result = v
		}
		if v, ok := strings.CutPrefix(f, "detail="); ok {
			detail = v
		}
	}
	return result, detail, line, wall, nil
}

func main() {
	var err error
	switch {
	case len(os.Args) == 2:
		err = run(os.Args[1])
	case len(os.Args) == 3 && os.Args[1] == "worker":
		err = runWorker(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: ech-probe-interop [worker] <path-to-cogbox>")
		os.Exit(64)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(cogbox string) error {
	cert, pool, err := selfSigned()
	if err != nil {
		return err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cfgBytes := echConfig(echConfID, priv.PublicKey().Bytes(), publicName)
	configList := u16(nil, len(cfgBytes))
	configList = append(configList, cfgBytes...)

	base := func() *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	}
	plain := base()
	alpn := base()
	alpn.NextProtos = []string{"h2"}
	retry := base()
	retry.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: cfgBytes, PrivateKey: priv.Bytes(), SendAsRetry: true}}
	noRetry := base()
	noRetry.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: cfgBytes, PrivateKey: priv.Bytes(), SendAsRetry: false}}
	byALPN := echByALPN(base(), retry.EncryptedClientHelloKeys)
	tls12 := &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12}
	p256 := base()
	p256.CurvePreferences = []tls.CurveID{tls.CurveP256}

	addrs := map[string]string{}
	for name, cfg := range map[string]*tls.Config{"plain": plain, "alpn": alpn, "ech-retry": retry, "ech-noretry": noRetry, "ech-by-alpn": byALPN, "tls12": tls12, "p256-only": p256} {
		a, err := serveTLS(cfg)
		if err != nil {
			return err
		}
		addrs[name] = a
	}
	// silent: reads the ClientHello and never answers.
	if addrs["silent"], err = serveRaw(func(c net.Conn) {
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.Copy(io.Discard, c)
	}); err != nil {
		return err
	}
	// closer: closes the moment it accepts.
	if addrs["closer"], err = serveRaw(func(c net.Conn) { c.Close() }); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "ech-probe-interop")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	ossl, osslCmd, err := serveOpenSSL(cert, tmp)
	if err != nil {
		return err
	}
	defer func() { osslCmd.Process.Kill(); osslCmd.Wait() }()
	addrs["openssl"] = ossl

	// Non-vacuity: the ECH server really decrypts ECH (a real client gets its
	// inner name accepted), and the plain server really speaks TLS 1.3.
	ec, err := tls.Dial("tcp", addrs["ech-retry"], &tls.Config{
		ServerName:                     denied,
		RootCAs:                        pool,
		EncryptedClientHelloConfigList: configList,
		MinVersion:                     tls.VersionTLS13,
	})
	if err != nil {
		return fmt.Errorf("non-vacuity: real ECH client against ech-retry: %v", err)
	}
	if st := ec.ConnectionState(); !st.ECHAccepted || st.ServerName != denied {
		ec.Close()
		return fmt.Errorf("non-vacuity: ech-retry did not accept ECH for %s (ECHAccepted=%v)", denied, st.ECHAccepted)
	}
	ec.Close()
	pc, err := tls.Dial("tcp", addrs["plain"], &tls.Config{ServerName: allowed, RootCAs: pool})
	if err != nil {
		return fmt.Errorf("non-vacuity: plain client against plain: %v", err)
	}
	if v := pc.ConnectionState().Version; v != tls.VersionTLS13 {
		pc.Close()
		return fmt.Errorf("non-vacuity: plain negotiated %#04x, not TLS 1.3", v)
	}
	pc.Close()

	cases := []probeCase{
		{name: "plain", addr: addrs["plain"], sni: allowed, result: "not-capable", details: []string{"ee-without-ech"}},
		{name: "alpn", addr: addrs["alpn"], sni: allowed, alpn: "h2,http/1.1", result: "not-capable", details: []string{"ee-without-ech"}},
		{name: "ech-retry", addr: addrs["ech-retry"], sni: allowed, result: "capable", details: []string{"retry-configs"}},
		{name: "ech-retry public_name", addr: addrs["ech-retry"], sni: publicName, result: "capable", details: []string{"retry-configs"}},
		// Pins the documented residual: this server sends no retry_configs, so
		// the probe reads it as not-capable, yet it still decrypts real ECH (the
		// same key as ech-retry). See docs/network-filtering.md.
		{name: "ech-noretry-residual", addr: addrs["ech-noretry"], sni: allowed, result: "not-capable", details: []string{"ee-without-ech"}},
		// The same server, keys or none by ALPN: capable under h2, not-capable
		// under acme-tls/1. The probe copies the guest's ALPN, so the gate's
		// cache must key on it (checks.l7-ech-gate drives that through the
		// worker).
		{name: "ech-by-alpn h2", addr: addrs["ech-by-alpn"], sni: publicName, alpn: "h2", result: "capable", details: []string{"retry-configs"}},
		{name: "ech-by-alpn acme-tls/1", addr: addrs["ech-by-alpn"], sni: publicName, alpn: "acme-tls/1", result: "not-capable", details: []string{"ee-without-ech"}},
		// OpenSSL, the other common TLS stack, with its own record framing.
		{name: "openssl", addr: addrs["openssl"], sni: allowed, alpn: "h2,http/1.1", result: "not-capable", details: []string{"ee-without-ech"}},
		{name: "tls12", addr: addrs["tls12"], sni: allowed, result: "unknown", details: []string{"alert", "not-tls13"}},
		// The probe offers X25519 alone (supported_groups and key_share), so a
		// conforming server has no group to ask for in a HelloRetryRequest: a
		// P-256-only server fails the handshake instead (handshake_failure).
		// The HRR path itself is pinned by the Zig unit tests.
		{name: "p256-only", addr: addrs["p256-only"], sni: allowed, result: "unknown", details: []string{"alert", "hrr"}},
		{name: "silent", addr: addrs["silent"], sni: allowed, result: "unknown", details: []string{"timeout"}, maxWall: 4500 * time.Millisecond},
		{name: "closer", addr: addrs["closer"], sni: allowed, result: "unknown", details: []string{"eof"}},
	}

	fails := 0
	fmt.Printf("%-24s %-12s %-16s %8s  %s\n", "case", "result", "detail", "wall", "line")
	for _, c := range cases {
		result, detail, line, wall, err := runProbe(cogbox, c)
		ok := err == nil && result == c.result
		if ok && len(c.details) > 0 {
			ok = false
			for _, d := range c.details {
				if detail == d {
					ok = true
				}
			}
		}
		if ok && c.maxWall > 0 && wall >= c.maxWall {
			ok = false
		}
		mark := "ok"
		if !ok {
			mark = "MISMATCH"
			fails++
		}
		fmt.Printf("%-24s %-12s %-16s %8s  %s  [%s]\n", c.name, result, detail, strconv.FormatInt(wall.Milliseconds(), 10)+"ms", line, mark)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", c.name, err)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "  %s: want result=%s detail in %v (max wall %v), got %q\n", c.name, c.result, c.details, c.maxWall, line)
		}
	}
	if fails > 0 {
		return fmt.Errorf("%d of %d probe cases mismatched", fails, len(cases))
	}
	return nil
}
