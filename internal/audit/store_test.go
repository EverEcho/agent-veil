package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestEmptyStoreRecentEncodesAsJSONArray(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "private", "audit.jsonl"), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.Recent(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "[]" {
		t.Fatalf("empty audit JSON=%s, want []", payload)
	}
}

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
	if err := store.Append(domain.AuditEvent{Timestamp: now, AgentID: "current", Action: domain.ActionRedact, FindingCount: 1, FindingTypes: []string{"pii.email"}, Preview: "这个是我邮箱 ***，请逐字返回"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(domain.AuditEvent{Timestamp: now, AgentID: secret, Action: domain.ActionBlock}); err == nil {
		t.Fatal("sensitive audit event was persisted")
	}
	events, err := store.Recent(now)
	if err != nil || len(events) != 1 || events[0].AgentID != "current" || events[0].Preview != "这个是我邮箱 ***，请逐字返回" {
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
	path := filepath.Join(t.TempDir(), "private", "audit.jsonl")
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
	path := filepath.Join(t.TempDir(), "private", "audit.jsonl")
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

func TestStoreRejectsRelativeUnsafeAndOversizedFiles(t *testing.T) {
	if _, err := NewStore("relative/audit.jsonl", time.Hour, nil); err == nil {
		t.Fatal("relative audit path was accepted")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, time.Hour, nil); err == nil {
		t.Fatal("world-readable audit file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxAuditFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, time.Hour, nil); err == nil {
		t.Fatal("oversized audit file was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewStore(path, time.Hour, nil); err == nil {
		t.Fatal("symlinked audit file was accepted")
	}
}

func TestStoreCompactsOldestEventsBeforeCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "audit.jsonl")
	store, err := NewStore(path, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.maxBytes = 260
	now := time.Now().UTC()
	for _, agentID := range []string{"first", "second", "third"} {
		if err := store.Append(domain.AuditEvent{Timestamp: now, AgentID: agentID, Action: domain.ActionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := store.Recent(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].AgentID != "third" {
		t.Fatalf("newest event was not retained: %+v", events)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > store.maxBytes {
		t.Fatalf("audit size=%d max=%d", info.Size(), store.maxBytes)
	}
}

func TestStoreRejectsDuplicateAuditKeys(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "audit.jsonl")
	payload := `{"timestamp":"2026-01-01T00:00:00Z","agent_id":"visible","agent_id":"hidden","action":"allow"}` + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, time.Hour, nil); err == nil {
		t.Fatal("audit event with duplicate identity was accepted")
	}
}

func TestStoreRejectsUnsafeAuditDirectories(t *testing.T) {
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Join(wide, "audit.jsonl"), time.Hour, nil); err == nil {
		t.Fatal("world-accessible audit directory was accepted")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewStore(filepath.Join(linked, "audit.jsonl"), time.Hour, nil); err == nil {
		t.Fatal("symlinked audit directory was accepted")
	}
}

func TestStoreRejectsUnknownOrLeakBearingPersistedAuditFields(t *testing.T) {
	for _, payload := range []string{
		`{"timestamp":"2026-01-01T00:00:00Z","agent_id":"safe","action":"allow","future":true}` + "\n",
		`{"timestamp":"2026-01-01T00:00:00Z","agent_id":"dev@example.com","action":"block"}` + "\n",
	} {
		directory := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "audit.jsonl")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(path, 100*365*24*time.Hour, nil); err == nil {
			t.Fatalf("unsafe persisted audit was accepted: %s", payload)
		}
	}
}
