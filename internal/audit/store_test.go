package audit

import (
	"os"
	"path/filepath"
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
}
