package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (roots, *os.File) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cbapp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := roots{filepath.Join(dir, "config"), filepath.Join(dir, "data"), filepath.Join(dir, "run")}
	for _, d := range []string{p.configDir("default"), p.runtime, p.data, filepath.Join(p.data, "instances", "default")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	l, err := lockFile(p.runtime+".lock", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	write(t, filepath.Join(p.runtime, "launch"), "v1 fixture 12 34\n", 0600)
	write(t, filepath.Join(p.runtime, "ssh-endpoint"), "2222 127.0.0.1\n", 0600)
	write(t, filepath.Join(p.data, "cogbox_ed25519"), "test private key\n", 0600)
	sshDir := filepath.Join(p.data, "instances", "default", "ssh")
	os.MkdirAll(sshDir, 0700)
	write(t, filepath.Join(sshDir, "ssh_host_ed25519_key.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fixture\n", 0644)
	if err := writeJSON(filepath.Join(p.configDir("default"), "environment.json"), environment{1, "local", "default"}); err != nil {
		t.Fatal(err)
	}
	return p, l
}
func write(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}
func globals(p roots) []string {
	return []string{"--config-root", p.config, "--data-root", p.data, "--runtime-root", p.runtime}
}
func fakeSSH(t *testing.T, dir string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(bin, "ssh"), "#!/bin/sh\ncat >/dev/null\nexit \"${APP_TEST_SSH_EXIT:-0}\"\n", 0700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The test relay implements the real one-line contract. Reusing an upstream
// connection would therefore expose an unstripped second path to the app.
func testRelay(t *testing.T, secret string) (endpoint, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	var mu sync.Mutex
	all := map[net.Conn]bool{}
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for c := range all {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			all[c] = true
			mu.Unlock()
			count.Add(1)
			go func() {
				defer c.Close()
				defer func() { mu.Lock(); delete(all, c); mu.Unlock() }()
				r := bufio.NewReader(c)
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				f := strings.Split(strings.TrimSpace(line), " ")
				if len(f) != 3 {
					return
				}
				prefix := "/_relay/" + secret + "/port/"
				if !strings.HasPrefix(f[1], prefix) {
					fmt.Fprint(c, "HTTP/1.1 403 Forbidden\r\nX-Cogbox-Relay: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					return
				}
				target := strings.TrimPrefix(f[1], prefix)
				digits, path, _ := strings.Cut(target, "/")
				port, _ := strconv.Atoi(digits)
				if port == 8080 {
					fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nX-Cogbox-Relay: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					return
				}
				u, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", digits))
				if err != nil {
					fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nX-Cogbox-Relay: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					return
				}
				defer u.Close()
				fmt.Fprintf(u, "%s /%s %s\r\n", f[0], path, f[2])
				go func() { io.Copy(u, r); u.Close() }()
				io.Copy(c, u)
			}()
		}
	}()
	return endpoint{1, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "v1 fixture 12 34"}, &count
}

func TestProxyContractAndOrigin(t *testing.T) {
	secret := strings.Repeat("a", 64)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "preview=yes; Path=/")
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/next")
			w.WriteHeader(302)
			return
		}
		fmt.Fprintf(w, "%s|%s|%s|%s", r.RequestURI, r.Host, r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-For"))
	}))
	defer app.Close()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(app.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	ep, count := testRelay(t, secret)
	conns := &connections{all: map[net.Conn]struct{}{}}
	defer conns.close()
	front := httptest.NewUnstartedServer(nil)
	authority := front.Listener.Addr().String()
	front.Config.Handler = proxyHandler(ep, secret, port, authority, func() bool { return true }, conns)
	front.Start()
	defer front.Close()
	client := front.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", front.URL+"/a%2Fb?q=a%2Bb", nil)
		req.Header.Set("X-Forwarded-For", "evil")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		want := "/a%2Fb?q=a%2Bb|127.0.0.1:" + portText + "|" + authority + "|127.0.0.1"
		if string(b) != want {
			t.Fatalf("got %q want %q", b, want)
		}
		if strings.Contains(string(b), secret) {
			t.Fatal("credential leaked")
		}
	}
	if count.Load() != 2 {
		t.Fatalf("expected two independent relay connections, got %d", count.Load())
	}
	for _, tc := range []struct{ host, origin, site string }{{"evil.example", "", ""}, {authority, "http://evil.example", ""}, {authority, "", "cross-site"}, {authority, "", "same-site"}, {authority, "null", ""}} {
		req, _ := http.NewRequest("GET", front.URL, nil)
		req.Host = tc.host
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Sec-Fetch-Site", tc.site)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("host/origin not rejected: %+v", tc)
		}
	}
	if count.Load() != 2 {
		t.Fatal("rejected browser request reached authenticated relay")
	}
	res, err := client.Get(front.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Location") != "/next" || res.Header.Get("Set-Cookie") != "preview=yes; Path=/" {
		t.Fatal("redirect/cookie rewritten")
	}
}

func TestProbeNeverFollowsRedirect(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Store(true) }))
	defer target.Close()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer relay.Close()
	addr := relay.Listener.Addr().(*net.TCPAddr)
	if checkRelay(context.Background(), endpoint{Host: "127.0.0.1", Port: addr.Port}, strings.Repeat("a", 64), func() bool { return true }) == nil || followed.Load() {
		t.Fatal("auth probe followed redirect")
	}
}

func TestStreamingAndWebSocket(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		io.Copy(c, rw)
	}))
	defer app.Close()
	port := app.Listener.Addr().(*net.TCPAddr).Port
	ep, _ := testRelay(t, strings.Repeat("a", 64))
	conns := &connections{all: map[net.Conn]struct{}{}}
	defer conns.close()
	front := httptest.NewUnstartedServer(nil)
	authority := front.Listener.Addr().String()
	front.Config.Handler = proxyHandler(ep, strings.Repeat("a", 64), port, authority, func() bool { return true }, conns)
	front.Start()
	defer front.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", front.URL+"/events", nil)
	res, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	res.Body.Close()
	if err != nil || line != "data: first\n" {
		t.Fatalf("SSE buffered: %q %v", line, err)
	}
	c, err := net.Dial("tcp", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "GET /socket HTTP/1.1\r\nHost: %s\r\nOrigin: http://%s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", authority, authority)
	r := bufio.NewReader(c)
	line, err = r.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("upgrade failed: %q %v", line, err)
	}
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	frame := []byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("WebSocket bytes changed: %x %v", got, err)
	}
	conns.close()
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("hijacked connection survived frontend closure")
	}
}

func TestControlNonceAndInvalidCLI(t *testing.T) {
	p, _ := fixture(t)
	if err := privateDir(p.appsDir()); err != nil {
		t.Fatal(err)
	}
	rec := record{Name: "default", Port: 3001, Nonce: strings.Repeat("a", 64), Socket: filepath.Join(p.appsDir(), "default-3001.sock")}
	ln, err := net.Listen("unix", rec.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveControl(ctx, ln, rec, cancel)
	wrong := rec
	wrong.Nonce = strings.Repeat("b", 64)
	if control(wrong, "stop") == nil {
		t.Fatal("wrong nonce stopped frontend")
	}
	if ctx.Err() != nil || control(rec, "ping") != nil {
		t.Fatal("bad nonce disrupted valid control")
	}
	if control(rec, "stop") != nil {
		t.Fatal("valid stop refused")
	}
	for _, args := range [][]string{{"open", "--port", "8080"}, {"open", "--port", "0"}, {"open", "--port", "3001", "--name", "../other"}, {"list", "--background"}, {"open", "--port", "3001", "extra"}} {
		if Run(context.Background(), append(globals(p), args...), io.Discard, io.Discard) == nil {
			t.Fatalf("accepted invalid CLI: %v", args)
		}
	}
}

func TestAuthorityAndPrivateFiles(t *testing.T) {
	p, _ := fixture(t)
	path := filepath.Join(p.configDir("default"), "environment.json")
	if err := writeJSON(path, environment{1, "unknown", "default"}); err != nil {
		t.Fatal(err)
	}
	if localOwner(p, "default", false) == nil {
		t.Fatal("unknown implicitly adopted")
	}
	if err := localOwner(p, "default", true); err != nil {
		t.Fatal(err)
	}
	var e environment
	if err := readJSON(path, &e, false); err != nil || e.Mode != "unknown" {
		t.Fatal("validation prematurely committed adoption")
	}
	writeJSON(path, environment{1, "cogworx", "default"})
	if localOwner(p, "default", true) == nil {
		t.Fatal("managed adopted")
	}
	writeJSON(path, environment{1, "local", "default"})
	t.Setenv("COGBOX_ENVIRONMENT", "cogworx")
	if localOwner(p, "default", false) == nil {
		t.Fatal("managed launch override ignored")
	}
	t.Setenv("COGBOX_ENVIRONMENT", "")
	secret, err := loadCredential(p, "default")
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadCredential(p, "default")
	if err != nil || secret != again {
		t.Fatal("credential not persistent")
	}
	cred := filepath.Join(p.configDir("default"), "app", "relay.json")
	if err := os.Chmod(cred, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredential(p, "default"); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	os.Remove(cred)
	if err := os.Symlink(path, cred); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredential(p, "default"); err == nil {
		t.Fatal("credential symlink followed")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(p.data, "environment.json"), path)
	if localOwner(p, "default", true) == nil {
		t.Fatal("guest-side authority symlink followed")
	}
}

func TestEndpointGenerationAndCanonicalRoot(t *testing.T) {
	p, lock := fixture(t)
	ep := endpoint{1, "127.0.0.1", 8123, "v1 fixture 12 34"}
	writeJSON(filepath.Join(p.runtime, "http-endpoint.json"), ep)
	if _, err := readEndpoint(p, "default"); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(p.configDir("default"), "config.json"), `{"httpPort":9999}`, 0600)
	got, err := readEndpoint(p, "default")
	if err != nil || got.Port != 8123 {
		t.Fatal("config edit changed live endpoint")
	}
	write(t, filepath.Join(p.runtime, "launch"), "v1 other 12 34\n", 0600)
	if live(p, "default", ep.Launch) {
		t.Fatal("new generation accepted")
	}
	write(t, filepath.Join(p.runtime, "launch"), ep.Launch, 0600)
	lock.Close()
	if live(p, "default", ep.Launch) {
		t.Fatal("stale identity accepted without lifetime lock")
	}
	alias := filepath.Join(filepath.Dir(p.runtime), "alias")
	os.Symlink(filepath.Dir(p.runtime), alias)
	resolved, err := canonicalRoot(filepath.Join(alias, "new", "run"))
	if err != nil || resolved != filepath.Join(filepath.Dir(p.runtime), "new", "run") {
		t.Fatalf("root alias not canonicalized: %q %v", resolved, err)
	}
}

func TestCLIBackgroundDuplicateStopAndLifetime(t *testing.T) {
	if testing.Short() {
		t.Skip("builds actual helper")
	}
	p, vmLock := fixture(t)
	fakeSSH(t, filepath.Dir(p.runtime))
	secret, err := loadCredential(p, "default")
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := testRelay(t, secret)
	writeJSON(filepath.Join(p.runtime, "http-endpoint.json"), ep)
	exe := filepath.Join(filepath.Dir(p.runtime), "cogbox-app")
	build := exec.Command("go", "build", "-o", exe, "./cmd/app")
	build.Dir = "../.."
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %s %v", b, err)
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(exe, append(globals(p), args...)...)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("app %v: %v %s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	url := run("open", "--port", "39001", "--background", "--no-browser")
	t.Cleanup(func() { exec.Command(exe, append(globals(p), "stop", "--port", "39001")...).Run() })
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("bad browser URL: %q", url)
	}
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 502 {
		t.Fatalf("absent application should remain reachable as 502: %d", res.StatusCode)
	}
	for i := 0; i < 12; i++ {
		if duplicate := run("open", "--name", "default", "--port", "39001", "--background", "--no-browser"); duplicate != url {
			t.Fatalf("duplicate changed URL %q != %q", duplicate, url)
		}
	}
	var items []listing
	if err := json.Unmarshal([]byte(run("list", "--json")), &items); err != nil || len(items) != 1 || items[0].URL != url {
		t.Fatalf("list: %+v %v", items, err)
	}
	if strings.Contains(run("list", "--json"), secret) {
		t.Fatal("secret in CLI output")
	}
	run("stop", "--port", "39001")
	if got := run("list", "--json"); got != "[]" {
		t.Fatalf("stopped list: %s", got)
	}
	// Where passwordless sudo is available, exercise the real privilege drop
	// against the launcher ownership layout: private user-owned launch/snapshot,
	// readable root-owned SSH endpoint. Sandboxed Nix checks omit only this leg.
	if os.Geteuid() != 0 && exec.Command("sudo", "-n", "true").Run() == nil {
		sshPath := filepath.Join(p.runtime, "ssh-endpoint")
		if err := os.Chmod(sshPath, 0644); err != nil {
			t.Fatal(err)
		}
		if b, err := exec.Command("sudo", "-n", "chown", "0:0", sshPath).CombinedOutput(); err != nil {
			t.Fatalf("sudo metadata setup: %s %v", b, err)
		}
		sudoArgs := []string{"-n", "env", "PATH=" + os.Getenv("PATH"), exe}
		sudoArgs = append(sudoArgs, globals(p)...)
		sudoArgs = append(sudoArgs, "open", "--port", "39002", "--background", "--no-browser")
		b, err := exec.Command("sudo", sudoArgs...).CombinedOutput()
		if err != nil || !strings.HasPrefix(string(b), "http://127.0.0.1:") {
			t.Fatalf("sudo open: %s %v", b, err)
		}
		run("stop", "--port", "39002")
	}
	url = run("open", "--port", "39001", "--background", "--no-browser")
	vmLock.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get(url); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("frontend survived VM lifetime")
}

func TestCLIRejectsForeignAdoptionWithoutCommitting(t *testing.T) {
	p, _ := fixture(t)
	fakeSSH(t, filepath.Dir(p.runtime))
	t.Setenv("APP_TEST_SSH_EXIT", "23")
	writeJSON(filepath.Join(p.configDir("default"), "environment.json"), environment{1, "unknown", "default"})
	writeJSON(filepath.Join(p.runtime, "http-endpoint.json"), endpoint{1, "127.0.0.1", 8123, "v1 fixture 12 34"})
	var out bytes.Buffer
	err := Run(context.Background(), append(globals(p), "open", "--port", "3001", "--adopt-local", "--no-browser"), &out, &out)
	if err == nil || !strings.Contains(err.Error(), "foreign") {
		t.Fatalf("wanted foreign refusal, got %v", err)
	}
	var env environment
	readJSON(filepath.Join(p.configDir("default"), "environment.json"), &env, false)
	if env.Mode != "unknown" {
		t.Fatal("foreign refusal committed adoption")
	}
}

func TestProvisionScriptPermissionsAndForeignState(t *testing.T) {
	dir := t.TempDir()
	guest := filepath.Join(dir, "guest")
	if err := os.Mkdir(guest, 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	logPath := filepath.Join(dir, "commands")
	write(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$APP_TEST_COMMAND_LOG\"\ncase \"$1\" in show) echo loaded;; esac\n", 0700)
	// A local guest's mapped 9p files report guest uid0 despite the host uid.
	write(t, filepath.Join(bin, "stat"), "#!/bin/sh\nprintf '0:0\\n'\n", 0700)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("APP_TEST_COMMAND_LOG", logPath)
	script := strings.NewReplacer("/var/lib/cogbox-state", filepath.Join(dir, "container"), "/var/lib/cogbox", guest, "/run/cogbox", filepath.Join(dir, "run")).Replace(generationGuard + provisionScript)
	write(t, filepath.Join(guest, ".app-launch"), "v1 fixture 12 34\n", 0644)
	secret := strings.Repeat("a", 64)
	run := func() error {
		cmd := exec.Command("sh", "-c", script)
		cmd.Stdin = strings.NewReader("v1 fixture 12 34\n" + secret + "\n")
		return cmd.Run()
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(guest, "app-relay.env")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("credential not private")
	}
	b, _ := os.ReadFile(logPath)
	if strings.Count(string(b), "restart") != 1 {
		t.Fatalf("initial restart missing: %s", b)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("matching credential retained broad permissions")
	}
	b, _ = os.ReadFile(logPath)
	if strings.Count(string(b), "restart") != 1 {
		t.Fatal("healthy matching credential restarted relay")
	}
	foreign := "COGBOX_APP_RELAY_SECRET=" + strings.Repeat("b", 64) + "\n"
	write(t, path, foreign, 0600)
	if err := run(); err == nil {
		t.Fatal("foreign credential accepted")
	}
	b, _ = os.ReadFile(path)
	if string(b) != foreign {
		t.Fatal("foreign credential changed")
	}
	os.Remove(path)
	outside := filepath.Join(dir, "outside")
	write(t, outside, "untouched", 0600)
	os.Symlink(outside, path)
	if run() == nil {
		t.Fatal("guest symlink accepted")
	}
	b, _ = os.ReadFile(outside)
	if string(b) != "untouched" {
		t.Fatal("followed guest symlink")
	}
	os.Remove(path)
	write(t, filepath.Join(guest, "claude-oauth.bound"), "", 0600)
	if run() == nil {
		t.Fatal("positive managed state accepted")
	}
	os.Remove(filepath.Join(guest, "claude-oauth.bound"))
	write(t, filepath.Join(guest, ".app-launch"), "v1 replacement 56 78\n", 0644)
	if run() == nil {
		t.Fatal("replacement guest generation accepted credential")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("replacement guest received credential file")
	}
}

func TestPostDialGenerationFence(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	liveNow := true
	dial := func(context.Context, string, string) (net.Conn, error) { liveNow = false; return a, nil }
	c, err := fencedDial(context.Background(), "tcp", "unused", dial, func() bool { return liveNow })
	if err == nil || c != nil {
		t.Fatal("connection to replacement generation escaped fence")
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if n, err := b.Read(one); n != 0 || err != io.EOF {
		t.Fatalf("replacement connection not closed before bytes: %d %v", n, err)
	}
}

func TestSSHGenerationSnapshotAndPinnedKey(t *testing.T) {
	p, _ := fixture(t)
	target, err := sshSnapshot(p, "default", "v1 fixture 12 34")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(target.knownHosts)
	args := strings.Join(target.args, "\n")
	for _, required := range []string{"StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "HostKeyAlias=cogbox-app-target", "HostKeyAlgorithms=ssh-ed25519", "UserKnownHostsFile=" + target.knownHosts} {
		if !strings.Contains(args, required) {
			t.Fatalf("missing pinned SSH option %s", required)
		}
	}
	b, err := readFile(target.knownHosts, true)
	if err != nil || strings.Contains(string(b), "fixture") {
		t.Fatalf("unsafe known_hosts %q %v", b, err)
	}
	write(t, filepath.Join(p.runtime, "ssh-endpoint"), "3333 127.0.0.1\n", 0600)
	if !strings.Contains(strings.Join(target.args, " "), "-p 2222") {
		t.Fatal("snapshot followed later endpoint edit")
	}
	write(t, filepath.Join(p.runtime, "launch"), "v1 replacement 56 78\n", 0600)
	if guestCommand(context.Background(), p, "default", "v1 fixture 12 34", target.args, "exit 0", "") == nil {
		t.Fatal("staging followed replacement generation")
	}
	if _, err := parseHostKey("ssh-ed25519 invalid\nmalicious entry"); err == nil {
		t.Fatal("host key newline accepted")
	}
}

func TestSSHRejectsReplacementServer(t *testing.T) {
	if testing.Short() {
		t.Skip("starts disposable SSH listener")
	}
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd unavailable")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	p, _ := fixture(t)
	dir := filepath.Dir(p.runtime)
	for _, name := range []string{"expected", "replacement"} {
		if b, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput(); err != nil {
			t.Fatalf("fixture host key: %s %v", b, err)
		}
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "expected.pub"))
	write(t, filepath.Join(p.data, "instances", "default", "ssh", "ssh_host_ed25519_key.pub"), string(pub), 0644)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	write(t, filepath.Join(p.runtime, "ssh-endpoint"), fmt.Sprintf("%d 127.0.0.1\n", port), 0600)
	conf := filepath.Join(dir, "sshd.conf")
	write(t, conf, fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nPasswordAuthentication no\nUsePAM no\n", port, filepath.Join(dir, "replacement"), filepath.Join(dir, "sshd.pid")), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := exec.CommandContext(ctx, sshd, "-D", "-e", "-f", conf)
	logFile, err := os.Create(filepath.Join(dir, "sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	server.Stderr = logFile
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); server.Wait() }()
	up := false
	for i := 0; i < 40; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err == nil {
			c.Close()
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		b, _ := os.ReadFile(filepath.Join(dir, "sshd.log"))
		t.Fatalf("disposable sshd did not start: %s", b)
	}
	target, err := sshSnapshot(p, "default", "v1 fixture 12 34")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(target.knownHosts)
	command := exec.Command("ssh", append(target.args, "cat")...)
	command.Stdin = strings.NewReader(strings.Repeat("a", 64) + "\n")
	b, err := command.CombinedOutput()
	if err == nil || (!strings.Contains(string(b), "Host key verification failed") && !strings.Contains(string(b), "REMOTE HOST IDENTIFICATION HAS CHANGED")) {
		t.Fatalf("replacement SSH host was not rejected at key verification: %s %v", b, err)
	}
}
