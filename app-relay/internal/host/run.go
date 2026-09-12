package host

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type options struct {
	command, name                             string
	port                                      int
	background, noBrowser, adopt, json, child bool
	nameSet                                   bool
}
type record struct {
	Name   string `json:"name"`
	Port   int    `json:"port"`
	URL    string `json:"url"`
	Launch string `json:"launch"`
	Nonce  string `json:"nonce"`
	Socket string `json:"socket"`
}
type listing struct {
	Name string `json:"name"`
	Port int    `json:"port"`
	URL  string `json:"url"`
}

// Run is also the CLI integration seam: tests invoke the real command parser
// and subprocess readiness/control protocol, not a parallel mock CLI.
func Run(ctx context.Context, args []string, out, errOut io.Writer) error {
	global := flag.NewFlagSet("cogbox app", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	var p roots
	global.StringVar(&p.config, "config-root", "", "resolved config root")
	global.StringVar(&p.data, "data-root", "", "resolved data root")
	global.StringVar(&p.runtime, "runtime-root", "", "resolved runtime root")
	if err := global.Parse(args); err != nil {
		return err
	}
	if len(global.Args()) == 0 {
		return errors.New("expected open, list, or stop")
	}
	if p.config == "" || p.data == "" || p.runtime == "" {
		return errors.New("invoke this helper through cogbox app")
	}
	if err := dropSudo(); err != nil {
		return err
	}
	// Resolve user-selected roots once, including macOS /tmp and /var aliases;
	// credential and guest-controlled descendants are still checked without following links.
	var err error
	for _, path := range []*string{&p.config, &p.data, &p.runtime} {
		*path, err = canonicalRoot(*path)
		if err != nil {
			return err
		}
	}
	args = global.Args()
	opt := options{command: args[0], name: "default"}
	fs := flag.NewFlagSet("app "+opt.command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opt.name, "name", "default", "instance")
	fs.StringVar(&opt.name, "n", "default", "instance")
	switch opt.command {
	case "open":
		fs.IntVar(&opt.port, "port", 0, "guest port")
		fs.BoolVar(&opt.background, "background", false, "background")
		fs.BoolVar(&opt.noBrowser, "no-browser", false, "no browser")
		fs.BoolVar(&opt.adopt, "adopt-local", false, "adopt local")
		fs.BoolVar(&opt.child, "child", false, "internal child")
	case "stop":
		fs.IntVar(&opt.port, "port", 0, "guest port")
	case "list":
		fs.BoolVar(&opt.json, "json", false, "JSON")
	default:
		return errors.New("expected open, list, or stop")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "name" || f.Name == "n" {
			opt.nameSet = true
		}
	})
	if !validName(opt.name) {
		return errors.New("instance name must start with a letter and contain only letters, digits, or hyphens (max 64 characters)")
	}
	if opt.command != "list" && (opt.port < 1 || opt.port > 65535 || opt.port == 8080) {
		return errors.New("choose a guest port from 1 to 65535 other than reserved port 8080")
	}
	if opt.child && opt.background {
		return errors.New("invalid background child invocation")
	}
	if opt.command == "list" {
		return list(p, opt, out)
	}
	if opt.command == "stop" {
		return stop(p, opt, out)
	}
	if opt.background {
		return background(ctx, p, opt, out, errOut)
	}
	return open(ctx, p, opt, out, errOut)
}

func validName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && ((c >= '0' && c <= '9') || c == '-') {
			continue
		}
		return false
	}
	return true
}
func canonicalRoot(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("host roots must be absolute")
	}
	cur := filepath.Clean(path)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		if cur == "/" {
			return "", err
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = filepath.Dir(cur)
	}
}
func dropSudo() error {
	if os.Geteuid() != 0 || os.Getenv("SUDO_USER") == "" {
		return nil
	}
	u, err := user.Lookup(os.Getenv("SUDO_USER"))
	if err != nil {
		return errors.New("cannot resolve original sudo user")
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid == 0 {
		return errors.New("invalid original sudo user")
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	if err = syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err = syscall.Setgid(gid); err != nil {
		return err
	}
	if err = syscall.Setuid(uid); err != nil {
		return err
	}
	os.Setenv("HOME", u.HomeDir)
	os.Unsetenv("SUDO_USER")
	os.Unsetenv("SUDO_UID")
	os.Unsetenv("SUDO_GID")
	return nil
}
func key(opt options) string                 { return opt.name + "-" + strconv.Itoa(opt.port) }
func recordPath(p roots, opt options) string { return filepath.Join(p.appsDir(), key(opt)+".json") }

func open(parent context.Context, p roots, opt options, out, errOut io.Writer) error {
	if err := localOwner(p, opt.name, opt.adopt); err != nil {
		return err
	}
	if err := privateDir(p.appsDir()); err != nil {
		return err
	}
	lock, err := lockFile(filepath.Join(p.appsDir(), key(opt)+".lock"), true)
	if err != nil {
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		for i := 0; i < 30; i++ {
			var rec record
			if readJSON(recordPath(p, opt), &rec, true) == nil && validRecord(p, rec) && rec.Name == opt.name && rec.Port == opt.port && live(p, rec.Name, rec.Launch) && control(rec, "ping") == nil {
				if err := ready(opt, rec.URL, out); err != nil {
					return err
				}
				if !opt.noBrowser && !opt.child {
					browser(rec.URL, errOut)
				}
				return nil
			}
			select {
			case <-parent.Done():
				return parent.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		return errors.New("another app open is still starting; retry shortly")
	}
	defer lock.Close()
	ep, err := readEndpoint(p, opt.name)
	if err != nil {
		return err
	}
	isLive := func() bool { return live(p, opt.name, ep.Launch) }
	sshTarget, err := sshSnapshot(p, opt.name, ep.Launch)
	if err != nil {
		return err
	}
	defer os.Remove(sshTarget.knownHosts)
	sshArgs := sshTarget.args
	// Per-instance lock serializes ownership, credential creation, and staging
	// across different application ports.
	if err := noSymlinks(p.configDir(opt.name)); err != nil {
		return err
	}
	provisionLock, err := lockFile(filepath.Join(p.configDir(opt.name), ".app-provision.lock"), false)
	if err != nil {
		return err
	}
	secret, err := func() (string, error) {
		defer provisionLock.Close()
		if err := localOwner(p, opt.name, opt.adopt); err != nil {
			return "", err
		}
		secret, err := loadCredential(p, opt.name)
		if err != nil {
			return "", err
		}
		if !live(p, opt.name, ep.Launch) {
			return "", errors.New("instance restarted during provisioning")
		}
		if err := guestCommand(parent, p, opt.name, ep.Launch, sshArgs, provisionScript, secret+"\n"); err != nil {
			return "", err
		}
		if probeErr := checkRelay(parent, ep, secret, isLive); probeErr != nil {
			// Recover a prior file-write success followed by a failed restart.
			// Ordinary repeated opens never restart a healthy relay.
			if !live(p, opt.name, ep.Launch) {
				return "", errors.New("instance restarted during provisioning")
			}
			if err := guestCommand(parent, p, opt.name, ep.Launch, sshArgs, "systemctl restart cogbox-app-relay.service", ""); err != nil {
				return "", err
			}
			for i := 0; i < 5; i++ {
				probeErr = checkRelay(parent, ep, secret, isLive)
				if probeErr == nil {
					break
				}
				select {
				case <-parent.Done():
					return "", parent.Err()
				case <-time.After(200 * time.Millisecond):
				}
			}
			if probeErr != nil {
				return "", probeErr
			}
		}
		if opt.adopt {
			if !live(p, opt.name, ep.Launch) {
				return "", errors.New("instance restarted during adoption")
			}
			if err := writeJSON(filepath.Join(p.configDir(opt.name), "environment.json"), environment{1, "local", opt.name}); err != nil {
				return "", err
			}
			if err := writeJSON(filepath.Join(p.data, "instances", opt.name, "environment.json"), environment{1, "local", opt.name}); err != nil {
				return "", err
			}
			if err := guestCommand(parent, p, opt.name, ep.Launch, sshArgs, "systemctl restart cogbox-environment.service", ""); err != nil {
				return "", errors.New("instance adopted locally but guest context refresh failed; restart the instance")
			}
		}
		return secret, nil
	}()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	nonce, err := randomToken()
	if err != nil {
		return err
	}
	rec := record{opt.name, opt.port, "http://" + ln.Addr().String() + "/", ep.Launch, nonce, filepath.Join(p.appsDir(), key(opt)+".sock")}
	if len(rec.Socket) > 100 {
		return errors.New("runtime path is too long for app control sockets; use a shorter XDG_RUNTIME_DIR")
	}
	if err := noSymlinks(rec.Socket); err != nil {
		return err
	}
	if err := os.Remove(rec.Socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	ctl, err := net.Listen("unix", rec.Socket)
	if err != nil {
		return err
	}
	defer ctl.Close()
	defer os.Remove(rec.Socket)
	if err := os.Chmod(rec.Socket, 0600); err != nil {
		return err
	}
	if err := writeJSON(recordPath(p, opt), rec); err != nil {
		return err
	}
	defer os.Remove(recordPath(p, opt))
	go serveControl(ctx, ctl, rec, cancel)
	conns := &connections{all: map[net.Conn]struct{}{}}
	defer conns.close()
	srv := &http.Server{Handler: proxyHandler(ep, secret, opt.port, ln.Addr().String(), isLive, conns), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(trackedListener{ln, conns}) }()
	defer srv.Close()
	if !isLive() {
		return errors.New("instance stopped before frontend readiness")
	}
	if err := ready(opt, rec.URL, out); err != nil {
		return err
	}
	if !opt.noBrowser && !opt.child {
		browser(rec.URL, errOut)
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-served:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			if !isLive() {
				return nil
			}
		}
	}
}

func ready(opt options, url string, out io.Writer) error {
	if opt.child {
		f := os.NewFile(3, "readiness")
		if f == nil {
			return errors.New("missing readiness pipe")
		}
		defer f.Close()
		return json.NewEncoder(f).Encode(map[string]string{"url": url})
	}
	_, err := fmt.Fprintln(out, url)
	return err
}

func background(ctx context.Context, p roots, opt options, out, errOut io.Writer) error {
	if err := privateDir(p.appsDir()); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	logPath := filepath.Join(p.appsDir(), key(opt)+".log")
	if err := noSymlinks(logPath); err != nil {
		w.Close()
		return err
	}
	fd, err := syscall.Open(logPath, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		w.Close()
		return err
	}
	logFile := os.NewFile(uintptr(fd), logPath)
	defer logFile.Close()
	args := []string{"--config-root", p.config, "--data-root", p.data, "--runtime-root", p.runtime, "open", "--name", opt.name, "--port", strconv.Itoa(opt.port), "--child", "--no-browser"}
	if opt.adopt {
		args = append(args, "--adopt-local")
	}
	cmd := exec.Command(exe, args...)
	cmd.ExtraFiles = []*os.File{w}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		w.Close()
		return err
	}
	w.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	msg := make(chan string, 1)
	go func() {
		var result map[string]string
		if json.NewDecoder(io.LimitReader(r, 4096)).Decode(&result) == nil {
			msg <- result["url"]
		} else {
			msg <- ""
		}
	}()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case url := <-msg:
		if !strings.HasPrefix(url, "http://127.0.0.1:") {
			cmd.Process.Kill()
			<-done
			return fmt.Errorf("frontend failed to start; inspect %s", logPath)
		}
		fmt.Fprintln(out, url)
		if !opt.noBrowser {
			browser(url, errOut)
		}
		return nil
	case <-ctx.Done():
		cmd.Process.Kill()
		<-done
		return ctx.Err()
	case <-timer.C:
		cmd.Process.Kill()
		<-done
		return errors.New("frontend readiness timed out")
	}
}

func browser(url string, errOut io.Writer) {
	tool := "xdg-open"
	if runtime.GOOS == "darwin" {
		tool = "open"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, tool, url).Run(); err != nil {
		fmt.Fprintln(errOut, "Could not open the browser automatically; open the printed URL.")
	}
}

func list(p roots, opt options, out io.Writer) error {
	items := []listing{}
	if err := noSymlinks(p.appsDir()); err != nil {
		return err
	}
	entries, err := os.ReadDir(p.appsDir())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var rec record
		if readJSON(filepath.Join(p.appsDir(), entry.Name()), &rec, true) != nil {
			continue
		}
		if opt.nameSet && rec.Name != opt.name {
			continue
		}
		if validRecord(p, rec) && control(rec, "ping") == nil && live(p, rec.Name, rec.Launch) {
			items = append(items, listing{rec.Name, rec.Port, rec.URL})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].Port < items[j].Port
	})
	if opt.json {
		return json.NewEncoder(out).Encode(items)
	}
	for _, rec := range items {
		fmt.Fprintf(out, "%s\t%d\t%s\n", rec.Name, rec.Port, rec.URL)
	}
	return nil
}

func stop(p roots, opt options, out io.Writer) error {
	var rec record
	if err := readJSON(recordPath(p, opt), &rec, true); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if !validRecord(p, rec) || rec.Name != opt.name || rec.Port != opt.port {
		return errors.New("invalid app control record")
	}
	if err := control(rec, "stop"); err != nil {
		return errors.New("frontend is not reachable; no process was signaled")
	}
	for i := 0; i < 30; i++ {
		if control(rec, "ping") != nil {
			fmt.Fprintln(out, "Stopped local app frontend.")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("frontend has not stopped yet")
}
func validRecord(p roots, r record) bool {
	return validName(r.Name) && r.Port > 0 && r.Port <= 65535 && len(r.Nonce) == 64 && r.Socket == filepath.Join(p.appsDir(), r.Name+"-"+strconv.Itoa(r.Port)+".sock")
}
