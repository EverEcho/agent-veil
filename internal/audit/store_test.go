package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestStoreUsesPrivatePermissionsRetentionAndLeakScan(t *testing.T) {
	secret := "sk-this-is-a-forbidden-test-secret"
	path := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	store, err := NewStore(path, 24*time.Hour, func() []string { return []string{secret} })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.Append(domain.AuditEvent{Timestamp: now.Add(-48 * time.Hour), AgentID: "old", Action: domain.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(domain.AuditEvent{Timestamp: now, AgentID: "current", Action: domain.ActionRedact}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(domain.AuditEvent{Timestamp: now, AgentID: secret, Action: domain.ActionBlock}); err == nil {
		t.Fatal("sensitive audit event was persisted")
	}
	events, err := store.Recent(now)
	if err != nil || len(events) != 1 || events[0].AgentID != "current" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("audit mode=%o", info.Mode().Perm())
	}
	persisted, _ := os.ReadFile(path)
	if strings.Contains(string(persisted), `"agent_id":"old"`) {
		t.Fatalf("expired event remained on disk: %s", persisted)
	}
}

func TestOpeningStorePrunesEventsOutsideRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewStore(path, 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(domain.AuditEvent{Timestamp: time.Now().UTC().Add(-2 * time.Hour), AgentID: "expired", Action: domain.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	persisted, _ := os.ReadFile(path)
	if strings.Contains(string(persisted), "expired") {
		t.Fatalf("expired event survived restart pruning: %s", persisted)
	}
}

func TestStoreDefaultLeakScanPreventsSensitivePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewStore(path, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(domain.AuditEvent{Timestamp: time.Now().UTC(), AgentID: "safe-agent", Action: domain.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(domain.AuditEvent{Timestamp: time.Now().UTC(), AgentID: "dev@example.com", Action: domain.ActionBlock}); err == nil {
		t.Fatal("default audit leak scan accepted sensitive metadata")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "dev@example.com") {
		t.Fatalf("sensitive metadata reached disk: %s", persisted)
	}
}
