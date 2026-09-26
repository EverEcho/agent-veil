package main

import (
	"bytes"
	"io"
	"sync"
)

// capabilityOutputWriter prevents Codex transport errors from printing a
// short-lived path capability into the terminal or desktop launch log.
type capabilityOutputWriter struct {
	mu      sync.Mutex
	dest    io.Writer
	secret  []byte
	pending []byte
}

func newCapabilityOutputWriter(dest io.Writer, routeToken string) *capabilityOutputWriter {
	return &capabilityOutputWriter{dest: dest, secret: []byte(routeToken)}
}

func (w *capabilityOutputWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.secret) == 0 {
		return w.dest.Write(payload)
	}
	var filtered bytes.Buffer
	for _, next := range payload {
		w.pending = append(w.pending, next)
		for len(w.pending) > 0 && !bytes.HasPrefix(w.secret, w.pending) {
			filtered.WriteByte(w.pending[0])
			w.pending = w.pending[1:]
		}
		if len(w.pending) == len(w.secret) {
			filtered.WriteString("[redacted-route-token]")
			w.pending = nil
		}
	}
	if filtered.Len() == 0 {
		return len(payload), nil
	}
	count, err := w.dest.Write(filtered.Bytes())
	if err == nil && count != filtered.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (w *capabilityOutputWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

func (w *capabilityOutputWriter) flushLocked() error {
	if len(w.pending) == 0 {
		return nil
	}
	count, err := w.dest.Write(w.pending)
	if err == nil && count != len(w.pending) {
		err = io.ErrShortWrite
	}
	w.pending = nil
	return err
}
