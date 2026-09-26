package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCapabilityOutputWriterRedactsTokenAcrossWrites(t *testing.T) {
	secret := strings.Repeat("a", 64)
	var output bytes.Buffer
	writer := newCapabilityOutputWriter(&output, secret)
	if _, err := writer.Write([]byte("ready\n")); err != nil || output.String() != "ready\n" {
		t.Fatalf("ordinary output was delayed: %q %v", output.String(), err)
	}
	for _, part := range []string{"connect ws://127.0.0.1/__veil/veil-v1:session:", secret[:17], secret[17:39], secret[39:], "/responses failed\n"} {
		if _, err := writer.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "[redacted-route-token]") || !strings.HasSuffix(output.String(), "/responses failed\n") {
		t.Fatalf("capability output was not redacted: %q", output.String())
	}
}
