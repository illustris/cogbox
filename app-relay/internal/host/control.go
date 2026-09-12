package host

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

type controlRequest struct {
	Nonce  string `json:"nonce"`
	Action string `json:"action"`
}

func control(rec record, action string) error {
	if err := noSymlinks(rec.Socket); err != nil {
		return err
	}
	c, err := net.DialTimeout("unix", rec.Socket, 300*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if err := json.NewEncoder(c).Encode(controlRequest{rec.Nonce, action}); err != nil {
		return err
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(c, 4096)).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		return errors.New("app control rejected request")
	}
	return nil
}
func serveControl(ctx context.Context, ln net.Listener, rec record, cancel context.CancelFunc) {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// The private local socket has one tiny request/response; bound each read
		// so a stale client cannot prevent stop or duplicate-open inspection.
		c.SetDeadline(time.Now().Add(time.Second))
		var req controlRequest
		if json.NewDecoder(io.LimitReader(c, 4096)).Decode(&req) != nil {
			c.Close()
			continue
		}
		ok := subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(rec.Nonce)) == 1 && (req.Action == "ping" || req.Action == "stop")
		json.NewEncoder(c).Encode(map[string]bool{"ok": ok})
		c.Close()
		if ok && req.Action == "stop" {
			cancel()
			return
		}
	}
}
