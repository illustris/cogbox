// Command app-relay is the guest half of the cogworx app proxy: a port-routed
// HTTP relay that lets the control plane reach a service the sandbox bound to
// its own loopback (a dev server on 127.0.0.1:3080, say) without that service
// having to listen on a routable address.
//
// It is deliberately NOT an HTTP server. It parses exactly ONE line per
// connection -- the request line -- rewrites it, and then splices both
// directions blind until EOF. That is what makes WebSocket upgrades, SSE and
// chunked bodies work with no protocol knowledge, and it is why the relay never
// touches, buffers or logs a header or a body.
//
// The wire protocol (v1) is specified in ../README.md and is a CROSS-REPO
// CONTRACT with the control plane's internal/web/appproxy.go. Change one side
// and you must change the other.
package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Wire-protocol tokens. These are the contract with the control plane; the CP
// builds the request-target this relay parses and keys its error mapping on the
// response header, so none of these may drift unilaterally.
const (
	relayPrefix = "/_relay/"
	portPrefix  = "port/"
	healthPath  = "/healthz"
	relayHeader = "X-Cogbox-Relay"

	// secretEnv names the per-instance secret the control plane derives and
	// stages into the guest. systemd (root) reads the 0600 env file and hands
	// it to this process, which runs unprivileged and could not open the file
	// itself -- see the unit in ../flake.nix.
	secretEnv = "COGBOX_APP_RELAY_SECRET"
)

const (
	defaultListen = "0.0.0.0:8080"

	// defaultMaxConns caps ROUTED connections. It is deliberately far above what
	// the control plane can ever ask for: the CP disables keep-alives, so every
	// browser request is its own relay connection, and a single cold page load of
	// a module-per-request dev server bursts to hundreds. The CP's own global
	// in-flight cap (256) is meant to be the binding constraint -- if this number
	// were the smaller one, an over-cap request would come back as a relay 503 in
	// the middle of a page load and the user would see a scatter of broken
	// subresources rather than any coherent error.
	defaultMaxConns = 512

	// acceptPerConn turns the routed cap into the ACCEPT cap. Accepting is bounded
	// separately because the head-read phase costs a goroutine and an 8 KiB buffer
	// before any secret has been seen, so it must not be unbounded just because
	// the routed cap is not reached yet.
	acceptPerConn = 4

	defaultHeadTimeout = 10 * time.Second
	defaultDialTimeout = 5 * time.Second
	defaultIdleTimeout = 60 * time.Minute

	// defaultBusyWait is how long a connection queues for a routed slot before it
	// is told 503. A burst above the cap is the normal shape of a page load, so it
	// should wait briefly rather than fail outright.
	defaultBusyWait = 2 * time.Second

	// defaultLinger bounds the upstream half of a splice once the CLIENT has
	// stopped talking. See proxy().
	defaultLinger = 5 * time.Second

	// maxRequestLine bounds the ONE line the relay reads. Anything longer is
	// refused with 431 rather than buffered, which is also the slowloris floor:
	// a client that never sends a newline is cut off by headTimeout.
	maxRequestLine = 8192

	// maxLogPath bounds the path in the per-connection journal line. The
	// request-target may be up to maxRequestLine bytes and every connection
	// writes one line, so the log must not be an amplifier for a caller that
	// holds the secret.
	maxLogPath = 256

	// maxLogMethod bounds the method for the same reason: it is only the request
	// line's first field, so it too may run to thousands of bytes. 32 is past
	// every real method.
	maxLogMethod = 32

	// Accept-retry backoff bounds, the http.Server.Serve shape.
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = 1 * time.Second
)

// httpError is a relay-GENERATED response. Every one of them carries
// X-Cogbox-Relay: 1 so the control plane can tell a relay refusal apart from
// the app's own status of the same number (an app's 502 must pass through
// unchanged). A zero code means "say nothing, just close".
type httpError struct {
	code   int
	reason string
	body   string
}

var (
	errClientGone  = &httpError{}
	errBadRequest  = &httpError{400, "Bad Request", "cogbox-app-relay: malformed request line\n"}
	errBadPort     = &httpError{400, "Bad Request", "cogbox-app-relay: bad port selector\n"}
	errForbidden   = &httpError{403, "Forbidden", "cogbox-app-relay: bad or missing relay secret\n"}
	errNotFound    = &httpError{404, "Not Found", "cogbox-app-relay: not a relay request\n"}
	errLineTooLong = &httpError{431, "Request Header Fields Too Large", "cogbox-app-relay: request line too long\n"}
	errUpstream    = &httpError{502, "Bad Gateway", "cogbox-app-relay: upstream dial failed\n"}
	errBusy        = &httpError{503, "Service Unavailable", "cogbox-app-relay: too many concurrent connections\n"}
)

// Route kinds. /healthz is the control plane's cheap liveness probe and is
// exempt from both the secret and the concurrency cap; everything else that is
// not a /_relay/ target is a 404.
const (
	routeProxy = iota
	routeHealth
)

type decision struct {
	kind int
	port int
	// line is the rewritten request line (CRLF-terminated) to send upstream,
	// with the whole /_relay/<secret>/port/<N> artifact stripped. The secret is
	// never forwarded to the app.
	line string
	// method and path are the journal's view of the request (see serveConn).
	// path is the rewritten target with the query cut off and the remainder
	// capped -- see logPath. Both are visible ASCII with no spaces, because
	// route() refuses a line that is anything else, so they log bare.
	method string
	path   string
}

type relay struct {
	secret      string
	selfPort    int
	maxConns    int
	maxAccept   int
	headTimeout time.Duration
	dialTimeout time.Duration
	idleTimeout time.Duration
	busyWait    time.Duration
	linger      time.Duration

	sem       chan struct{}
	acceptSem chan struct{}
	logf      func(format string, v ...interface{})
}

func newRelay(r relay) *relay {
	if r.maxConns <= 0 {
		r.maxConns = defaultMaxConns
	}
	if r.maxAccept <= 0 {
		r.maxAccept = r.maxConns * acceptPerConn
	}
	if r.headTimeout <= 0 {
		r.headTimeout = defaultHeadTimeout
	}
	if r.dialTimeout <= 0 {
		r.dialTimeout = defaultDialTimeout
	}
	if r.idleTimeout <= 0 {
		r.idleTimeout = defaultIdleTimeout
	}
	if r.busyWait <= 0 {
		r.busyWait = defaultBusyWait
	}
	if r.linger <= 0 {
		r.linger = defaultLinger
	}
	if r.logf == nil {
		r.logf = log.Printf
	}
	r.sem = make(chan struct{}, r.maxConns)
	r.acceptSem = make(chan struct{}, r.maxAccept)
	return &r
}

// listen binds and records the relay's OWN port, which is the one port the
// selector may never name: routing to it would loop the relay onto itself.
func (r *relay) listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		r.selfPort = ta.Port
	}
	return ln, nil
}

// serve accepts until the listener is permanently gone. Two things it will NOT
// do: die on a transient accept error, and accept without a bound.
//
// Dying is the worse failure of the two. The unit is Restart=always, so a
// process that exits on a descriptor shortage restarts every RestartSec into the
// same shortage and systemd's start limit eventually parks the service in
// `failed` -- at which point nothing listens on :8080 at all and the control
// plane cannot even tell "relay wedged" from "plugin not installed". Riding it
// out loudly is the only posture that self-heals.
func (r *relay) serve(ln net.Listener) error {
	var (
		backoff     time.Duration
		dropped     int
		lastDropLog time.Time
	)
	for {
		c, err := ln.Accept()
		if err != nil {
			if !retryableAccept(err) {
				return err
			}
			// EMFILE and friends: the listener is fine, the process is out of
			// room. Back off (the http.Server.Serve shape) and keep going.
			if backoff *= 2; backoff == 0 {
				backoff = minAcceptBackoff
			}
			if backoff > maxAcceptBackoff {
				backoff = maxAcceptBackoff
			}
			r.logf("accept: %v -- retrying in %s (the listener is still up)", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0

		// Admission BEFORE the goroutine and the 8 KiB read buffer: this is the
		// bound on the head-read phase, which happens before any secret has been
		// checked and is therefore reachable by anything that can route to the
		// guest. Over the cap the connection is closed unread -- no response, no
		// buffer, no goroutine.
		select {
		case r.acceptSem <- struct{}{}:
		default:
			c.Close()
			dropped++
			// Rate-limited: the flood that trips this must not also be a way to
			// flood the journal.
			if time.Since(lastDropLog) > time.Second {
				r.logf("accept cap %d full: dropped %d connection(s) unread", r.maxAccept, dropped)
				dropped, lastDropLog = 0, time.Now()
			}
			continue
		}
		go func() {
			defer func() { <-r.acceptSem }()
			r.serveConn(c)
		}()
	}
}

// retryableAccept separates "this listener is dead" from "the process is out of
// room for a moment". Only the first is worth exiting on.
func retryableAccept(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false // the listener is gone for good; there is nothing to retry onto
	}
	// EMFILE/ENFILE are the descriptor-exhaustion case a connect flood produces,
	// and the whole reason this function exists. EINTR/ECONNABORTED are the
	// ordinary transient ones (the net package already swallows those, but an
	// accept error must never be fatal by omission).
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EINTR) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// serveConn handles one connection: one request head in, then a blind splice.
// The connection is never reused for a second head -- the control plane opens a
// fresh one per request, which is what keeps a port selector from being smuggled
// across a pipelined follow-up request.
func (r *relay) serveConn(c net.Conn) {
	start := time.Now()
	remote := c.RemoteAddr().String()
	port := 0
	// method and path stay "-" until route() hands back a decision, which it
	// only does once the secret has verified (or for /healthz, which needs
	// none). A refused connection may be holding a wrong or partial secret, so
	// nothing derived from its target is written down.
	method, path := "-", "-"
	result := "closed"
	var up, down int64
	// One journald line per connection: the port, the method, the stripped
	// path, the outcome and the byte counts. Never a query string, never a
	// header, never a body, never the secret.
	defer func() {
		r.logf("conn remote=%s port=%d method=%s path=%s result=%s up=%d down=%d dur=%s",
			remote, port, method, path, result, up, down, time.Since(start).Round(time.Millisecond))
	}()
	defer c.Close()

	// idle 0 for now: the head read runs under the explicit headTimeout deadline
	// below, and the splice turns the idle refresh on once the head is in.
	ic := newIdleConn(c, 0)
	br := bufio.NewReaderSize(ic, maxRequestLine)

	_ = c.SetReadDeadline(time.Now().Add(r.headTimeout))
	line, herr := readRequestLine(br)
	if herr != nil {
		result = r.fail(c, herr)
		return
	}
	dec, herr := r.route(line)
	if herr != nil {
		result = r.fail(c, herr)
		return
	}
	method, path = dec.method, dec.path
	if dec.kind == routeHealth {
		result = "200"
		r.respond(c, 200, "OK", "ok\n")
		return
	}
	port = dec.port
	up, down, result = r.proxy(c, ic, br, dec)
}

// readRequestLine reads the single request line, leaving every following byte
// buffered in br for the splice.
func readRequestLine(br *bufio.Reader) (string, *httpError) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errLineTooLong
	}
	if err != nil {
		if len(line) == 0 {
			// A port scan or a half-open probe: nothing was said, say nothing.
			return "", errClientGone
		}
		return "", errBadRequest
	}
	return string(line), nil
}

// route parses and validates the request line. It is pure (no I/O) so the
// protocol can be table-tested.
func (r *relay) route(line string) (decision, *httpError) {
	if len(line) > maxRequestLine {
		return decision{}, errLineTooLong
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")

	// Exactly three single-space-separated fields; a double space, a tab or a
	// missing field is a malformed line, not something to be lenient about.
	f := strings.Split(line, " ")
	if len(f) != 3 {
		return decision{}, errBadRequest
	}
	method, target, version := f[0], f[1], f[2]
	for _, s := range f {
		// Visible ASCII only. This is where control characters, DEL and any
		// 8-bit byte are refused, so nothing that reaches the rewritten line
		// can inject a second request line into the upstream stream.
		if s == "" || !visibleASCII(s) {
			return decision{}, errBadRequest
		}
	}
	if version != "HTTP/1.1" && version != "HTTP/1.0" {
		return decision{}, errBadRequest
	}
	// Origin-form only. Absolute-form (http://host/...), authority-form
	// (CONNECT host:port) and asterisk-form all fail here: the relay speaks
	// only to a loopback app and must never take a host from the client.
	if method == "CONNECT" || target[0] != '/' {
		return decision{}, errBadRequest
	}

	if method == "GET" && target == healthPath {
		return decision{kind: routeHealth, method: method, path: target}, nil
	}
	if !strings.HasPrefix(target, relayPrefix) {
		return decision{}, errNotFound
	}
	secret, after, ok := strings.Cut(target[len(relayPrefix):], "/")
	if !ok || !strings.HasPrefix(after, portPrefix) {
		return decision{}, errBadRequest
	}
	// The secret is checked BEFORE the port, so a caller who does not hold it
	// learns nothing about which ports are live inside the sandbox.
	if !r.secretOK(secret) {
		return decision{}, errForbidden
	}

	digits := after[len(portPrefix):]
	n := 0
	for n < len(digits) && digits[n] >= '0' && digits[n] <= '9' {
		n++
	}
	if n == 0 || n > 5 {
		return decision{}, errBadPort
	}
	port, err := strconv.Atoi(digits[:n])
	if err != nil || port < 1 || port > 65535 || port == r.selfPort {
		return decision{}, errBadPort
	}

	rest := digits[n:]
	switch {
	case rest == "":
		rest = "/"
	case rest[0] == '/':
		// already a clean origin-form path
	case rest[0] == '?':
		rest = "/" + rest
	default:
		return decision{}, errBadRequest
	}
	return decision{
		kind:   routeProxy,
		port:   port,
		line:   method + " " + rest + " " + version + "\r\n",
		method: logMethod(method),
		path:   logPath(rest),
	}, nil
}

// logPath is the journal's view of a rewritten target. The query is cut off --
// apps put their own tokens in query strings, and so does the control plane's
// redeem hop -- and what is left is capped, because a request-target is allowed
// to be far longer than a log line should be. The path itself is kept: it is
// what makes a per-connection line say anything useful about what was fetched.
func logPath(rest string) string {
	p, _, _ := strings.Cut(rest, "?")
	if len(p) > maxLogPath {
		return p[:maxLogPath] + "..."
	}
	return p
}

// logMethod is the journal's view of the method, capped for the same reason the
// path is. Nothing else is done to it: route() has already refused anything that
// is not visible ASCII, so it cannot forge a field or a newline.
func logMethod(m string) string {
	if len(m) > maxLogMethod {
		return m[:maxLogMethod] + "..."
	}
	return m
}

// secretOK is the whole authentication story. Unprovisioned (no secret in the
// environment) means FAIL CLOSED: every /_relay/ request is refused, so a
// sandbox that missed its staging can never run open on the VPC. /healthz stays
// answerable so the control plane can still tell "relay up" from "relay absent".
func (r *relay) secretOK(got string) bool {
	if r.secret == "" {
		return false
	}
	// Constant-time in the value; the LENGTH is fixed by the protocol (64 hex
	// chars) and is not a secret, so an early length mismatch leaks nothing.
	return subtle.ConstantTimeCompare([]byte(got), []byte(r.secret)) == 1
}

// proxy dials the loopback app and splices. It returns the byte counts and the
// log result.
func (r *relay) proxy(c net.Conn, ic *idleConn, br *bufio.Reader, dec decision) (up, down int64, result string) {
	if !r.acquireSlot() {
		return 0, 0, r.fail(c, errBusy)
	}
	defer func() { <-r.sem }()

	ctx, cancel := context.WithTimeout(context.Background(), r.dialTimeout)
	defer cancel()
	// 127.0.0.1 ONLY, as an IPv4 literal. The port is the sole client-influenced
	// input to this dial; the host never is.
	upc, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(dec.port)))
	if err != nil {
		return 0, 0, r.fail(c, errUpstream)
	}
	defer upc.Close()

	// The head is in; from here both halves live under the idle timeout, which
	// is refreshed on every read and write so a long-lived WebSocket or SSE
	// stream survives while a truly idle connection does not.
	_ = c.SetDeadline(time.Time{})
	ic.setIdle(r.idleTimeout)
	uic := newIdleConn(upc, r.idleTimeout)

	if _, err := uic.Write([]byte(dec.line)); err != nil {
		return 0, 0, r.fail(c, errUpstream)
	}

	done := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(uic, br)
		// The CLIENT has stopped talking. Per the wire protocol the control plane
		// opens one connection per request head and never half-closes, so this is
		// the end of the exchange and not a client that is merely done with its
		// request body: half-close upstream so a dev server sees the body EOF,
		// then put the upstream half on a short leash. Without that leash an
		// endpoint that holds a SILENT response stream open (SSE, long poll) --
		// whose browser tab was just closed -- would keep this connection, and the
		// cap slot under it, for the whole 60-minute idle timeout, with /healthz
		// still cheerfully answering "ok" while the relay ran out of slots.
		uic.CloseWrite()
		uic.setIdle(r.linger)
		done <- n
	}()
	down, _ = io.Copy(ic, uic)
	ic.CloseWrite()
	// The upstream is done talking, so the exchange is over. Tear both halves
	// down explicitly rather than letting a client that holds its write side
	// open ride the 60-minute idle timeout while holding a cap slot.
	_ = upc.Close()
	_ = c.Close()
	up = <-done
	return up, down, "splice"
}

// acquireSlot takes one of the routed-connection slots, waiting a bounded moment
// rather than refusing a burst outright: a page load is dozens of connections
// arriving at once, and a 503 in the middle of one shows up in the browser as a
// scatter of broken subresources, not as an error anyone can act on. The wait is
// safe to hold because the ACCEPT cap already bounds how many connections can be
// queued here at all.
func (r *relay) acquireSlot() bool {
	select {
	case r.sem <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(r.busyWait)
	defer t.Stop()
	select {
	case r.sem <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

func (r *relay) fail(c net.Conn, e *httpError) string {
	if e.code == 0 {
		return "closed"
	}
	r.respond(c, e.code, e.reason, e.body)
	return strconv.Itoa(e.code)
}

// respond writes a relay-generated response. X-Cogbox-Relay marks it as ours
// and Connection: close matches the one-head-per-connection rule.
func (r *relay) respond(c net.Conn, code int, reason, body string) {
	_ = c.SetWriteDeadline(time.Now().Add(r.headTimeout))
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n"+
		"%s: 1\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", code, reason, relayHeader, len(body), body)
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// idleConn refreshes a deadline before every read and write, giving the splice
// an idle timeout rather than a total-duration one. net.Conn deadline setters
// are safe for concurrent use, which the two splice directions rely on; the
// timeout itself is atomic because one direction shortens it for the other (see
// setIdle).
type idleConn struct {
	net.Conn
	idle atomic.Int64 // time.Duration
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	ic := &idleConn{Conn: c}
	ic.idle.Store(int64(idle))
	return ic
}

// setIdle changes the idle timeout and applies it IMMEDIATELY, including to a
// read that is already blocked -- which is the whole point of it: shortening the
// leash has to move the deadline now, not at the next Read call that may never
// come.
func (c *idleConn) setIdle(d time.Duration) {
	c.idle.Store(int64(d))
	if d > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(d))
	}
}

func (c *idleConn) Read(p []byte) (int, error) {
	if d := time.Duration(c.idle.Load()); d > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(d))
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if d := time.Duration(c.idle.Load()); d > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(d))
	}
	return c.Conn.Write(p)
}

// CloseWrite half-closes so the peer sees a real EOF instead of waiting out the
// idle timeout. net.Conn does not declare it, so it cannot be promoted from the
// embedded interface.
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		log.Printf("ignoring %s=%q (want a positive integer); using %d", key, v, def)
		return def
	}
	return n
}

func envDur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("ignoring %s=%q (want a positive Go duration, e.g. 30s); using %s", key, v, def)
		return def
	}
	return d
}

func main() {
	log.SetFlags(0) // journald stamps the time
	log.SetPrefix("cogbox-app-relay: ")

	listen := flag.String("listen", envStr("COGBOX_RELAY_LISTEN", defaultListen),
		"host:port to listen on (env COGBOX_RELAY_LISTEN)")
	flag.Parse()

	r := newRelay(relay{
		secret:      os.Getenv(secretEnv),
		maxConns:    envInt("COGBOX_RELAY_MAX_CONNS", defaultMaxConns),
		headTimeout: envDur("COGBOX_RELAY_HEAD_TIMEOUT", defaultHeadTimeout),
		dialTimeout: envDur("COGBOX_RELAY_DIAL_TIMEOUT", defaultDialTimeout),
		idleTimeout: envDur("COGBOX_RELAY_IDLE_TIMEOUT", defaultIdleTimeout),
	})

	ln, err := r.listen(*listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	if r.secret == "" {
		// Loud, and the only safe posture: the control plane has not staged
		// this instance's secret, so the relay refuses everything but /healthz.
		log.Printf("no %s in the environment -- FAIL CLOSED: every /_relay/ request is refused with 403 (%s still answers)", secretEnv, healthPath)
	}
	log.Printf("listening on %s (max %d routed / %d accepted, head %s, dial %s, idle %s)",
		ln.Addr(), r.maxConns, r.maxAccept, r.headTimeout, r.dialTimeout, r.idleTimeout)
	// serve rides out every transient accept error, so a return means the listener
	// itself is gone -- the one case where exiting (and letting systemd restart
	// us) is better than looping.
	log.Fatalf("listener is gone: %v", r.serve(ln))
}
