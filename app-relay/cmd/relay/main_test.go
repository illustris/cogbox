package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// testSecret is a FIXTURE, not a real secret: 64 lowercase hex characters, the
// shape the control plane derives with HMAC-SHA256(serverKey, instanceID).
const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// selfPort is what the table-test relay pretends to be listening on, so the
// self-loop rejection can be asserted against the protocol's documented 8080.
const selfPort = 8080

func quiet(string, ...interface{}) {}

func TestRouteRequestLine(t *testing.T) {
	r := newRelay(relay{secret: testSecret, logf: quiet})
	r.selfPort = selfPort

	cases := []struct {
		name       string
		line       string
		wantCode   int    // 0 == accepted
		wantKind   int    // when accepted
		wantPort   int    // when routeProxy
		wantLine   string // when routeProxy
		wantMethod string // when accepted: the journal's method
		wantPath   string // when accepted: the journal's stripped path
	}{
		{
			name: "path and query", line: "GET /_relay/" + testSecret + "/port/3080/app?x=1 HTTP/1.1\r\n",
			wantKind: routeProxy, wantPort: 3080, wantLine: "GET /app?x=1 HTTP/1.1\r\n",
			// The query goes upstream but never into the log line.
			wantMethod: "GET", wantPath: "/app",
		},
		{
			name: "bare selector becomes root", line: "GET /_relay/" + testSecret + "/port/3080 HTTP/1.1\r\n",
			wantKind: routeProxy, wantPort: 3080, wantLine: "GET / HTTP/1.1\r\n",
			wantMethod: "GET", wantPath: "/",
		},
		{
			name: "query directly after the selector", line: "GET /_relay/" + testSecret + "/port/3080?q=1 HTTP/1.1\r\n",
			wantKind: routeProxy, wantPort: 3080, wantLine: "GET /?q=1 HTTP/1.1\r\n",
			wantMethod: "GET", wantPath: "/",
		},
		{
			name: "root path", line: "POST /_relay/" + testSecret + "/port/1/ HTTP/1.0\r\n",
			wantKind: routeProxy, wantPort: 1, wantLine: "POST / HTTP/1.0\r\n",
			wantMethod: "POST", wantPath: "/",
		},
		{
			name: "bare LF is accepted", line: "GET /_relay/" + testSecret + "/port/65535/x HTTP/1.1\n",
			wantKind: routeProxy, wantPort: 65535, wantLine: "GET /x HTTP/1.1\r\n",
			wantMethod: "GET", wantPath: "/x",
		},
		{
			// A request-target may be thousands of bytes; one log line per
			// connection must not be a way to write them all to the journal.
			name:     "long path is capped in the journal view",
			line:     "GET /_relay/" + testSecret + "/port/3080/" + strings.Repeat("a", 400) + " HTTP/1.1\r\n",
			wantKind: routeProxy, wantPort: 3080,
			wantLine:   "GET /" + strings.Repeat("a", 400) + " HTTP/1.1\r\n",
			wantMethod: "GET", wantPath: "/" + strings.Repeat("a", maxLogPath-1) + "...",
		},
		{
			// And so may the method: it is only the request line's first field.
			name:     "long method is capped in the journal view",
			line:     strings.Repeat("M", 200) + " /_relay/" + testSecret + "/port/3080/ HTTP/1.1\r\n",
			wantKind: routeProxy, wantPort: 3080,
			wantLine:   strings.Repeat("M", 200) + " / HTTP/1.1\r\n",
			wantMethod: strings.Repeat("M", maxLogMethod) + "...", wantPath: "/",
		},
		{name: "healthz", line: "GET /healthz HTTP/1.1\r\n", wantKind: routeHealth, wantMethod: "GET", wantPath: healthPath},

		{name: "self-loop port", line: "GET /_relay/" + testSecret + "/port/8080/ HTTP/1.1\r\n", wantCode: 400},
		{name: "port zero", line: "GET /_relay/" + testSecret + "/port/0/ HTTP/1.1\r\n", wantCode: 400},
		{name: "port out of range", line: "GET /_relay/" + testSecret + "/port/65536/ HTTP/1.1\r\n", wantCode: 400},
		{name: "port too many digits", line: "GET /_relay/" + testSecret + "/port/000003080/ HTTP/1.1\r\n", wantCode: 400},
		{name: "non-numeric port", line: "GET /_relay/" + testSecret + "/port/http/ HTTP/1.1\r\n", wantCode: 400},
		{name: "empty port", line: "GET /_relay/" + testSecret + "/port//x HTTP/1.1\r\n", wantCode: 400},
		{name: "junk after the port digits", line: "GET /_relay/" + testSecret + "/port/3080x HTTP/1.1\r\n", wantCode: 400},
		{name: "missing port segment", line: "GET /_relay/" + testSecret + "/3080/ HTTP/1.1\r\n", wantCode: 400},

		{name: "empty secret", line: "GET /_relay//port/3080/ HTTP/1.1\r\n", wantCode: 403},
		{name: "wrong secret same length", line: "GET /_relay/" + strings.Repeat("f", 64) + "/port/3080/ HTTP/1.1\r\n", wantCode: 403},
		{name: "truncated secret", line: "GET /_relay/" + testSecret[:63] + "/port/3080/ HTTP/1.1\r\n", wantCode: 403},
		{name: "secret checked before the port", line: "GET /_relay/nope/port/8080/ HTTP/1.1\r\n", wantCode: 403},

		{name: "empty line", line: "\r\n", wantCode: 400},
		{name: "not a request line", line: "hello\r\n", wantCode: 400},
		{name: "double space", line: "GET  /_relay/x/port/1/ HTTP/1.1\r\n", wantCode: 400},
		{name: "absolute form", line: "GET http://app.example.com/ HTTP/1.1\r\n", wantCode: 400},
		{name: "connect", line: "CONNECT app.example.com:443 HTTP/1.1\r\n", wantCode: 400},
		{name: "asterisk form", line: "OPTIONS * HTTP/1.1\r\n", wantCode: 400},
		{name: "unsupported version", line: "GET /_relay/" + testSecret + "/port/3080/ HTTP/2.0\r\n", wantCode: 400},
		{name: "control character in target", line: "GET /_relay/" + testSecret + "/port/3080/a\x01b HTTP/1.1\r\n", wantCode: 400},
		{name: "tab separator", line: "GET\t/healthz HTTP/1.1\r\n", wantCode: 400},

		{name: "not a relay target", line: "GET /admin HTTP/1.1\r\n", wantCode: 404},
		{name: "healthz is GET only", line: "POST /healthz HTTP/1.1\r\n", wantCode: 404},
		{name: "prefix without a slash", line: "GET /_relayx/ HTTP/1.1\r\n", wantCode: 404},

		{
			name:     "oversized request line",
			line:     "GET /_relay/" + testSecret + "/port/3080/" + strings.Repeat("a", maxRequestLine) + " HTTP/1.1\r\n",
			wantCode: 431,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := r.route(tc.line)
			if tc.wantCode != 0 {
				if err == nil {
					t.Fatalf("route(%q) accepted, want %d", tc.line, tc.wantCode)
				}
				if err.code != tc.wantCode {
					t.Fatalf("route(%q) = %d, want %d", tc.line, err.code, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("route(%q) = %d %s, want accepted", tc.line, err.code, err.reason)
			}
			if dec.kind != tc.wantKind {
				t.Fatalf("kind = %d, want %d", dec.kind, tc.wantKind)
			}
			if dec.method != tc.wantMethod {
				t.Errorf("journal method = %q, want %q", dec.method, tc.wantMethod)
			}
			if dec.path != tc.wantPath {
				t.Errorf("journal path = %q, want %q", dec.path, tc.wantPath)
			}
			// The journal's view of the target is derived from the REWRITTEN
			// path, so the routing artifact cannot ride into a log line.
			if strings.Contains(dec.path, testSecret) || strings.Contains(dec.path, relayPrefix) {
				t.Errorf("journal path carries the routing artifact: %q", dec.path)
			}
			if tc.wantKind != routeProxy {
				return
			}
			if dec.port != tc.wantPort {
				t.Errorf("port = %d, want %d", dec.port, tc.wantPort)
			}
			if dec.line != tc.wantLine {
				t.Errorf("rewritten line = %q, want %q", dec.line, tc.wantLine)
			}
			if strings.Contains(dec.line, testSecret) {
				t.Errorf("rewritten line still carries the secret: %q", dec.line)
			}
		})
	}
}

// The relay must refuse every proxied request when the control plane has not
// staged a secret -- an unprovisioned instance may never run open.
func TestUnprovisionedFailsClosed(t *testing.T) {
	r := newRelay(relay{secret: "", logf: quiet})
	r.selfPort = selfPort

	for _, line := range []string{
		"GET /_relay/" + testSecret + "/port/3080/ HTTP/1.1\r\n",
		"GET /_relay//port/3080/ HTTP/1.1\r\n",
	} {
		if _, err := r.route(line); err == nil || err.code != 403 {
			t.Fatalf("route(%q) = %v, want 403", line, err)
		}
	}
	// /healthz stays answerable so the control plane can still distinguish
	// "relay up but unprovisioned" from "relay absent".
	if dec, err := r.route("GET /healthz HTTP/1.1\r\n"); err != nil || dec.kind != routeHealth {
		t.Fatalf("healthz = %v/%v, want the health route", dec, err)
	}
}

// ---------------------------------------------------------------- live relay

func startRelay(t *testing.T, cfg relay) string {
	t.Helper()
	if cfg.logf == nil {
		cfg.logf = quiet
	}
	r := newRelay(cfg)
	ln, err := r.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = r.serve(ln) }()
	return ln.Addr().String()
}

func startUpstream(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func dialRelay(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// readHead reads a request head (request line + headers) off a connection.
func readHead(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if line == "\r\n" {
			return sb.String(), nil
		}
	}
}

func TestProxyRoundTrip(t *testing.T) {
	heads := make(chan string, 1)
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		head, err := readHead(bufio.NewReader(c))
		if err != nil {
			return
		}
		heads <- head
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	})
	addr := startRelay(t, relay{secret: testSecret})

	c := dialRelay(t, addr)
	fmt.Fprintf(c, "GET /_relay/%s/port/%d/app?x=1 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Probe: 1\r\n\r\n",
		testSecret, upstream, upstream)

	var head string
	select {
	case head = <-heads:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never saw a request")
	}
	wantLine := "GET /app?x=1 HTTP/1.1\r\n"
	if !strings.HasPrefix(head, wantLine) {
		t.Errorf("upstream request line = %q, want prefix %q", head, wantLine)
	}
	// The routing artifact is stripped and the secret never reaches the app.
	if strings.Contains(head, testSecret) || strings.Contains(head, "/_relay/") {
		t.Errorf("upstream head still carries the routing artifact: %q", head)
	}
	// Headers are passed through verbatim -- the relay parses only the line.
	if !strings.Contains(head, "X-Probe: 1\r\n") || !strings.Contains(head, fmt.Sprintf("Host: 127.0.0.1:%d\r\n", upstream)) {
		t.Errorf("upstream head lost a passed-through header: %q", head)
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	// The app's own response must pass through untouched -- no relay marker.
	if resp.Header.Get(relayHeader) != "" {
		t.Errorf("app response carries %s, want it only on relay-generated responses", relayHeader)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
}

func TestProxyClosedPortIs502(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	addr := startRelay(t, relay{secret: testSecret})
	c := dialRelay(t, addr)
	fmt.Fprintf(c, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, dead)

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if resp.Header.Get(relayHeader) != "1" {
		t.Errorf("%s = %q, want \"1\"", relayHeader, resp.Header.Get(relayHeader))
	}
	// net/http folds Connection: close into resp.Close.
	if !resp.Close {
		t.Error("relay-generated response did not carry Connection: close")
	}
}

func TestHealthzIsSecretExempt(t *testing.T) {
	// No secret staged at all: /healthz must still answer.
	addr := startRelay(t, relay{secret: ""})
	c := dialRelay(t, addr)
	io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get(relayHeader) != "1" {
		t.Errorf("%s = %q, want \"1\"", relayHeader, resp.Header.Get(relayHeader))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}

func TestUnprovisionedRelayRefusesOverTheWire(t *testing.T) {
	upstream := startUpstream(t, func(c net.Conn) { c.Close() })
	addr := startRelay(t, relay{secret: ""})

	c := dialRelay(t, addr)
	fmt.Fprintf(c, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get(relayHeader) != "1" {
		t.Errorf("%s = %q, want \"1\"", relayHeader, resp.Header.Get(relayHeader))
	}
}

func TestMaxConnsIs503AndHealthzIsExempt(t *testing.T) {
	accepted := make(chan struct{}, 4)
	release := make(chan struct{})
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		accepted <- struct{}{}
		<-release // hold the connection open, so the relay holds its cap slot
	})
	t.Cleanup(func() { close(release) })

	// busyWait short so the test asserts the refusal, not the queueing (which
	// TestBurstQueuesForASlot covers); maxAccept explicit so the ROUTED cap is the
	// only one under test here.
	addr := startRelay(t, relay{secret: testSecret, maxConns: 1, maxAccept: 8, busyWait: 50 * time.Millisecond})

	held := dialRelay(t, addr)
	fmt.Fprintf(held, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the first connection never reached the upstream")
	}

	over := dialRelay(t, addr)
	fmt.Fprintf(over, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	resp, err := http.ReadResponse(bufio.NewReader(over), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if resp.Header.Get(relayHeader) != "1" {
		t.Errorf("%s = %q, want \"1\"", relayHeader, resp.Header.Get(relayHeader))
	}

	// /healthz is exempt from the cap: the liveness probe must not be the first
	// thing to fail when a sandbox is busy.
	hc := dialRelay(t, addr)
	io.WriteString(hc, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
	hresp, err := http.ReadResponse(bufio.NewReader(hc), nil)
	if err != nil {
		t.Fatalf("read healthz response: %v", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != 200 {
		t.Errorf("healthz status = %d, want 200 while the cap is full", hresp.StatusCode)
	}
}

// A burst above the routed cap is the normal shape of a page load (the control
// plane opens one connection per request), so it must queue briefly rather than
// come back as a scatter of 503s in the middle of a page.
func TestBurstQueuesForASlot(t *testing.T) {
	var seen atomic.Int64
	first := make(chan struct{})
	release := make(chan struct{})
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		if _, err := readHead(br); err != nil {
			return
		}
		if seen.Add(1) == 1 {
			close(first)
			<-release // the first connection holds the only routed slot
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
	})
	addr := startRelay(t, relay{secret: testSecret, maxConns: 1, maxAccept: 8, busyWait: 10 * time.Second})

	held := dialRelay(t, addr)
	fmt.Fprintf(held, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the first connection never reached the upstream")
	}

	over := dialRelay(t, addr)
	fmt.Fprintf(over, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	// The slot frees while the second connection is still queued.
	time.AfterFunc(100*time.Millisecond, func() { close(release) })

	resp, err := http.ReadResponse(bufio.NewReader(over), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200: the queued connection was refused instead of waiting", resp.StatusCode)
	}
}

// The head-read phase runs BEFORE any secret has been seen, so it needs a bound
// of its own: a goroutine and an 8 KiB buffer per accepted connection is exactly
// what a connect flood from anything that can route to the guest would spend.
func TestAcceptCapDropsWithoutAResponse(t *testing.T) {
	accepted := make(chan struct{}, 2)
	release := make(chan struct{})
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		accepted <- struct{}{}
		<-release
	})
	t.Cleanup(func() { close(release) })

	addr := startRelay(t, relay{secret: testSecret, maxAccept: 1})

	held := dialRelay(t, addr)
	fmt.Fprintf(held, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the first connection never reached the upstream")
	}

	// Over the accept cap: closed unread, with no response written at all. An
	// over-cap peer must not even get a buffer allocated for it.
	over := dialRelay(t, addr)
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf [1]byte
	n, err := over.Read(buf[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("over-cap connection got %d byte(s)/%v, want 0/EOF", n, err)
	}
}

// A descriptor shortage must not be fatal: exiting here means systemd's start
// limit eventually parks the unit in `failed` and nothing listens on :8080 at
// all, which the control plane cannot tell apart from "plugin not installed".
func TestRetryableAccept(t *testing.T) {
	emfile := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	if !retryableAccept(emfile) {
		t.Error("EMFILE classified as fatal; a connect flood would take the relay down permanently")
	}
	if !retryableAccept(os.NewSyscallError("accept", syscall.ENFILE)) {
		t.Error("ENFILE classified as fatal")
	}
	if retryableAccept(net.ErrClosed) {
		t.Error("a closed listener classified as retryable; serve would spin forever")
	}
}

// A WebSocket upgrade is the reason the relay splices blind instead of speaking
// HTTP: after the 101 there is no HTTP left to parse in either direction.
func TestWebSocketUpgradeSplicesBothWays(t *testing.T) {
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		if _, err := readHead(br); err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		// Raw, non-HTTP echo of whatever the client sends after the upgrade.
		io.Copy(c, br)
	})
	addr := startRelay(t, relay{secret: testSecret})

	c := dialRelay(t, addr)
	fmt.Fprintf(c, "GET /_relay/%s/port/%d/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		testSecret, upstream)

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	if _, err := io.WriteString(c, "\x81\x04ping"); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echoed frame: %v", err)
	}
	if string(got) != "\x81\x04ping" {
		t.Errorf("echoed frame = %q, want %q", got, "\x81\x04ping")
	}
}

// A client that goes away mid-stream must not pin its cap slot for the idle
// timeout. The shape: an SSE or long-poll endpoint that holds a SILENT response
// stream open, and a browser tab that closes. The client->upstream copy ends,
// but a silent upstream sends nothing for the other copy to notice, so without
// the linger the connection -- and the slot under it -- would sit there for the
// full 60 minutes while /healthz still answered "ok".
func TestAbandonedStreamReleasesItsSlot(t *testing.T) {
	var seen atomic.Int64
	first := make(chan struct{})
	release := make(chan struct{})
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		if _, err := readHead(br); err != nil {
			return
		}
		if seen.Add(1) == 1 {
			close(first)
			<-release // head accepted, nothing ever sent back
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
	})
	t.Cleanup(func() { close(release) })

	addr := startRelay(t, relay{
		secret: testSecret, maxConns: 1, maxAccept: 8,
		linger: 200 * time.Millisecond, idleTimeout: time.Hour,
		// Long enough that a slot which is never released fails this test as a
		// 503 rather than as a hang.
		busyWait: 5 * time.Second,
	})

	gone, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	fmt.Fprintf(gone, "GET /_relay/%s/port/%d/events HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned connection never reached the upstream")
	}
	gone.Close() // the tab closes

	c := dialRelay(t, addr)
	fmt.Fprintf(c, "GET /_relay/%s/port/%d/ HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200: the abandoned stream never released its slot", resp.StatusCode)
	}
}

func TestClientHangupIsSilent(t *testing.T) {
	logged := make(chan string, 4)
	addr := startRelay(t, relay{
		secret: testSecret,
		logf:   func(f string, v ...interface{}) { logged <- fmt.Sprintf(f, v...) },
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close() // a bare TCP probe: connect, say nothing, go away

	select {
	case line := <-logged:
		if !strings.Contains(line, "result=closed") {
			t.Errorf("log line = %q, want result=closed", line)
		}
		// Nothing was said, so there is nothing to say about a target.
		if !strings.Contains(line, "method=- path=-") {
			t.Errorf("log line = %q, want method=- path=- for a connection that never sent a request line", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no log line for a hung-up connection")
	}
}

// ------------------------------------------------------------ journal line

// waitForConnLine returns the next per-connection journal line, ignoring any
// other output (an accept-loop warning, say) the relay may have produced.
func waitForConnLine(t *testing.T, logged <-chan string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case line := <-logged:
			if strings.HasPrefix(line, "conn remote=") {
				return line
			}
		case <-deadline:
			t.Fatal("no per-connection log line")
			return ""
		}
	}
}

// The occupant of a sandbox already sees every request its own app serves, so
// the per-connection line names the method and the path -- otherwise a journal
// full of "port=3080 result=splice" says nothing about what was fetched. What it
// must not name is the query string, where both apps and the control plane's own
// redeem hop put tokens.
func TestConnLogCarriesMethodAndPath(t *testing.T) {
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		if _, err := readHead(bufio.NewReader(c)); err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
	})
	logged := make(chan string, 8)
	addr := startRelay(t, relay{
		secret: testSecret,
		logf:   func(f string, v ...interface{}) { logged <- fmt.Sprintf(f, v...) },
	})

	c := dialRelay(t, addr)
	fmt.Fprintf(c, "GET /_relay/%s/port/%d/foo?tok=s3cr3t HTTP/1.1\r\nHost: x\r\n\r\n", testSecret, upstream)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	line := waitForConnLine(t, logged)
	if !strings.Contains(line, "method=GET path=/foo result=splice") {
		t.Errorf("log line = %q, want method=GET path=/foo result=splice", line)
	}
	if strings.Contains(line, "tok=") || strings.Contains(line, "s3cr3t") {
		t.Errorf("log line carries the query string: %q", line)
	}
	if strings.Contains(line, testSecret) || strings.Contains(line, relayPrefix) {
		t.Errorf("log line carries the routing artifact: %q", line)
	}
}

// The secret rides in the request TARGET, so anything path-derived in the log
// is a place it could leak. route() verifies the secret before it returns a
// decision, which is what lets a refused connection -- one that may be holding a
// wrong or partial secret -- log method=- path=- and nothing else.
func TestConnLogNeverCarriesTheSecret(t *testing.T) {
	upstream := startUpstream(t, func(c net.Conn) {
		defer c.Close()
		if _, err := readHead(bufio.NewReader(c)); err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
	})
	logged := make(chan string, 16)
	addr := startRelay(t, relay{
		secret: testSecret,
		logf:   func(f string, v ...interface{}) { logged <- fmt.Sprintf(f, v...) },
	})

	wrongSecret := strings.Repeat("f", 64)
	cases := []struct {
		name    string
		target  string
		refused bool // no decision was returned, so nothing may be said about the target
	}{
		{"routed", fmt.Sprintf("/_relay/%s/port/%d/dash", testSecret, upstream), false},
		{"wrong secret", "/_relay/" + wrongSecret + "/port/3080/dash", true},
		{"bad port with a good secret", fmt.Sprintf("/_relay/%s/port/0/dash", testSecret), true},
		{"not a relay target", "/admin", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dialRelay(t, addr)
			fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", tc.target)
			// Every one of these ends with the relay closing the connection.
			io.Copy(io.Discard, c)

			line := waitForConnLine(t, logged)
			for _, bad := range []string{testSecret, wrongSecret, relayPrefix} {
				if strings.Contains(line, bad) {
					t.Errorf("log line carries %q: %q", bad, line)
				}
			}
			if tc.refused {
				if !strings.Contains(line, "method=- path=-") {
					t.Errorf("log line = %q, want method=- path=- for a refused connection", line)
				}
			} else if !strings.Contains(line, "method=GET path=/dash") {
				t.Errorf("log line = %q, want method=GET path=/dash", line)
			}
		})
	}
}
