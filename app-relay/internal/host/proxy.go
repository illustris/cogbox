package host

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Track both ordinary and hijacked connections: Server.Close does not close a
// WebSocket, and no old app socket may outlive its VM generation.
type connections struct {
	mu  sync.Mutex
	all map[net.Conn]struct{}
}
type trackedConn struct {
	net.Conn
	owner *connections
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.all, c)
	c.owner.mu.Unlock()
	return err
}
func (c *connections) wrap(conn net.Conn) net.Conn {
	t := &trackedConn{conn, c}
	c.mu.Lock()
	c.all[t] = struct{}{}
	c.mu.Unlock()
	return t
}
func (c *connections) close() {
	c.mu.Lock()
	var all []net.Conn
	for conn := range c.all {
		all = append(all, conn)
	}
	c.mu.Unlock()
	for _, conn := range all {
		conn.Close()
	}
}

type trackedListener struct {
	net.Listener
	conns *connections
}

func fencedDial(ctx context.Context, network, addr string, dial func(context.Context, string, string) (net.Conn, error), isLive func() bool) (net.Conn, error) {
	if !isLive() {
		return nil, errors.New("instance stopped")
	}
	c, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if !isLive() {
		c.Close()
		return nil, errors.New("instance restarted during connection")
	}
	return c, nil
}

func (l trackedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return l.conns.wrap(c), nil
}

func proxyHandler(ep endpoint, secret string, port int, authority string, isLive func() bool, conns *connections) http.Handler {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, ResponseHeaderTimeout: 30 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, e := fencedDial(ctx, network, addr, dialer.DialContext, isLive)
				if e != nil {
					return nil, e
				}
				return conns.wrap(c), nil
			}},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = relayAddress(ep)
			prefix := "/_relay/" + secret + "/port/" + strconv.Itoa(port)
			pr.Out.URL.Path = prefix + pr.In.URL.Path
			pr.Out.URL.RawPath = prefix + pr.In.URL.EscapedPath()
			pr.SetXForwarded()
			pr.Out.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			pr.Out.Header.Del("X-Cogbox-Relay")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "guest application is unavailable", http.StatusBadGateway)
		},
		ModifyResponse: func(res *http.Response) error {
			// Never leak an internal redirect carrying the credential.
			if strings.Contains(res.Header.Get("Location"), secret) {
				res.Header.Del("Location")
			}
			res.Header.Del("X-Cogbox-Relay")
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site := r.Header.Get("Sec-Fetch-Site")
		if r.Host != authority || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+authority) || (site != "" && site != "none" && site != "same-origin") {
			http.Error(w, "local app origin required", http.StatusForbidden)
			return
		}
		if !isLive() {
			http.Error(w, "instance stopped or restarted", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}
