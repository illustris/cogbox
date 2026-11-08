//go:build !linux

package main

import "errors"

// runWorker needs Linux namespaces (see worker.go).
func runWorker(string) error {
	return errors.New("worker mode needs Linux (unshare -rnm)")
}
