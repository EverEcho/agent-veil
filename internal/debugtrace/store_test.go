package debugtrace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestDeveloperTraceStoreRequiresExplicitBodyCapture(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	store, err := NewStore(filepath.Join(directory, "developer.json"), filepath.Join(directory, "developer-traces.jsonl"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trace := RequestTrace{Timestamp: time.Now().UTC(), SessionID: "session-1", Findings: []Finding{}, RequestBefore: `{"input":"dev@example.com"}`, RequestAfter: `{"input":"[[VEIL_token]]"}`}
	if err := store.Append(trace); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "developer-traces.jsonl")); !os.IsNotExist(err) {
		t.Fatal("disabled developer mode created a trace log")
	}
	if err := store.SaveSettings(Settings{SchemaVersion: "v1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(trace); err != nil {
		t.Fatal(err)
	}
	stored, _ := os.ReadFile(filepath.Join(directory, "developer-traces.jsonl"))
	if strings.Contains(string(stored), "dev@example.com") || strings.Contains(string(stored), "VEIL_token") {
		t.Fatalf("metadata-only trace retained request bodies: %s", stored)
	}
	if err := store.SaveSettings(Settings{SchemaVersion: "v1", Enabled: true, CaptureRequestBodies: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(trace); err != nil {
		t.Fatal(err)
	}
	stored, _ = os.ReadFile(filepath.Join(directory, "developer-traces.jsonl"))
	if !strings.Contains(string(stored), "dev@example.com") || !strings.Contains(string(stored), "VEIL_token") {
		t.Fatalf("explicit full request capture omitted bodies: %s", stored)
	}
	for _, name := range []string{"developer.json", "developer-traces.jsonl"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%v", name, info.Mode().Perm())
		}
	}
}

func TestDeveloperSettingsRejectBodyCaptureWhileDisabled(t *testing.T) {
	if err := (Settings{SchemaVersion: "v1", CaptureRequestBodies: true}).Validate(); err == nil {
		t.Fatal("body capture without developer mode was accepted")
	}
}

func TestCaptureBodyIsBounded(t *testing.T) {
	body := []byte(strings.Repeat("x", MaxCapturedBodyBytes+10))
	captured, truncated := CaptureBody(body)
	if !truncated || len(captured) != MaxCapturedBodyBytes {
		t.Fatalf("captured=%d truncated=%v", len(captured), truncated)
	}
}

func TestTraceStorePrunesExpiredEntries(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	store, err := NewStore(filepath.Join(directory, "developer.json"), filepath.Join(directory, "developer-traces.jsonl"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSettings(Settings{SchemaVersion: "v1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, trace := range []RequestTrace{{Timestamp: now.Add(-2 * time.Hour), AgentID: "old", Findings: []Finding{}}, {Timestamp: now, AgentID: "new", Protocol: domain.ProtocolOpenAIResponses, Findings: []Finding{}}} {
		if err := store.Append(trace); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Prune(now); err != nil {
		t.Fatal(err)
	}
	traces, err := store.Recent(now, 100)
	if err != nil || len(traces) != 1 || traces[0].AgentID != "new" {
		t.Fatalf("traces=%+v err=%v", traces, err)
	}
}
