package diagnostic

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
)

func TestReportHashesIdentitiesAndSecondarilyRedactsFields(t *testing.T) {
	scanner := detector.NewDefault()
	secret := "AKIAIOSFODNN7EXAMPLE"
	if canary := os.Getenv("VEIL_TEST_LEAK_CANARY"); canary != "" {
		secret = canary
	}
	report, err := Build(scanner, time.Now().UTC(), "ok", 1, []Agent{{Reference: "agent-raw", Kind: secret, Version: "1.0", State: "active"}}, []domain.AuditEvent{{SessionID: "session-raw", AgentID: "agent-raw", SurfaceID: "primary", FindingTypes: []string{secret}, Action: domain.ActionBlock}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Marshal(scanner, report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, forbidden := range []string{secret, "agent-raw", "session-raw"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("diagnostic payload leaked %q: %s", forbidden, text)
		}
	}
	if strings.Count(text, "[redacted]") != 2 || !strings.Contains(text, "sha256:") {
		t.Fatalf("diagnostic payload was not sanitized: %s", text)
	}
}

type failingScanner struct{}

func (failingScanner) ScanChecked(string, string) ([]detector.Match, error) {
	return nil, domain.NewError(domain.ErrDetectorFailure, "test", "failed")
}

func TestReportFailsClosedWhenSecondaryScannerFails(t *testing.T) {
	if _, err := Build(failingScanner{}, time.Now().UTC(), "ok", 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Marshal(failingScanner{}, Report{}); err == nil {
		t.Fatal("diagnostic export ignored scanner failure")
	}
}
