package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type roots struct{ config, data, runtime string }

func (p roots) configDir(name string) string { return filepath.Join(p.config, "instances", name) }
func (p roots) runtimeDir(name string) string {
	if name == "default" {
		return p.runtime
	}
	return p.runtime + "-" + name
}
func (p roots) appsDir() string { return p.runtime + "-apps" }

// Reject symlinks at every component of host authority/credential paths. State
// mounted into a guest is never used as a source of local ownership.
func noSymlinks(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return errors.New("host paths must be absolute")
	}
	for cur := path; cur != string(filepath.Separator); cur = filepath.Dir(cur) {
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink at %s", cur)
		}
	}
	return nil
}

func privateDir(path string) error {
	if err := noSymlinks(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be private (mode 0700)", path)
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || int(s.Uid) != os.Geteuid() {
		return errors.New("host directory belongs to another user")
	}
	return nil
}

func readFile(path string, private bool) ([]byte, error) {
	if err := noSymlinks(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("expected a regular host file")
	}
	if private && st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("host credential/control file must have mode 0600")
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || (int(s.Uid) != os.Geteuid() && (private || s.Uid != 0)) {
		return nil, errors.New("host file belongs to another user")
	}
	b, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if len(b) > 64*1024 {
		return nil, errors.New("host metadata is too large")
	}
	return b, err
}

func writeJSON(path string, value any) error {
	if err := noSymlinks(path); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".app-tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func readJSON(path string, dst any, private bool) error {
	b, err := readFile(path, private)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func lockFile(path string, nonblock bool) (*os.File, error) {
	if err := noSymlinks(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	flags := syscall.LOCK_EX
	if nonblock {
		flags |= syscall.LOCK_NB
	}
	if err := syscall.Flock(fd, flags); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type endpoint struct {
	Version int    `json:"version"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Launch  string `json:"launch"`
}

func readEndpoint(p roots, name string) (endpoint, error) {
	var ep endpoint
	if err := readJSON(filepath.Join(p.runtimeDir(name), "http-endpoint.json"), &ep, false); err != nil {
		return ep, errors.New("missing live HTTP endpoint; start or restart the instance with current cogbox")
	}
	if ep.Version != 1 || ep.Port < 1 || ep.Port > 65535 || len(strings.Fields(ep.Launch)) != 4 {
		return ep, errors.New("invalid live HTTP endpoint; restart the instance")
	}
	// Local frontend connections must never follow a hostname or a remote target.
	if ep.Host == "0.0.0.0" {
		ep.Host = "127.0.0.1"
	}
	if ep.Host != "127.0.0.1" && ep.Host != "::1" {
		return ep, errors.New("local app relay requires a loopback HTTP endpoint")
	}
	if !live(p, name, ep.Launch) {
		return ep, errors.New("instance is stopped or restarting")
	}
	return ep, nil
}

func live(p roots, name, launch string) bool {
	b, err := readFile(filepath.Join(p.runtimeDir(name), "launch"), false)
	if err != nil || strings.TrimSpace(string(b)) != launch {
		return false
	}
	// A held lifetime lock is authoritative on Linux and Darwin. Never signal a
	// PID, and never trust a stale launch/pid file on its own.
	fd, err := syscall.Open(p.runtimeDir(name)+".lock", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		syscall.Flock(fd, syscall.LOCK_UN)
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
