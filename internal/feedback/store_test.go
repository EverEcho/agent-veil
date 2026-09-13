package feedback

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
)

func validEntry() Entry {
	return Entry{Timestamp: time.Now().UTC(), RuleID: "pii.email", Category: "pii.email", Detector: "regex", Severity: domain.SeverityHigh, Confidence: 1, SuggestedAction: domain.ActionRedact, PolicyAction: domain.ActionAsk, Scope: policy.Scope{AgentID: "agent-a", FindingType: "pii.email"}}
}

func TestStorePersistsOnlyValidatedMetadataPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "feedback.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(validEntry()); err != nil {
		t.Fatal(err)
	}
	entries, err := store.Recent()
	if err != nil || len(entries) != 1 || entries[0].Scope.FindingType != "pii.email" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
}

func TestStoreRejectsUnsafePathsFilesAndMetadata(t *testing.T) {
	if _, err := NewStore("relative/feedback.json"); err == nil {
		t.Fatal("relative feedback path was accepted")
	}
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Join(wide, "feedback.json")); err == nil {
		t.Fatal("world-accessible feedback directory was accepted")
	}
	path := filepath.Join(t.TempDir(), "private", "feedback.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	invalid := validEntry()
	invalid.Scope.FindingType = "secret.private_key"
	if err := store.Append(invalid); err == nil {
		t.Fatal("mismatched feedback scope was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"v1","entries":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Recent(); err == nil {
		t.Fatal("world-readable feedback file was accepted")
	}
	target := filepath.Join(filepath.Dir(path), "target.json")
	if err := os.WriteFile(target, []byte(`{"schema_version":"v1","entries":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := store.Recent(); err == nil {
		t.Fatal("symlinked feedback file was accepted")
	}
}

func TestStoreRejectsAmbiguousOrUnknownDocuments(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	store, err := NewStore(filepath.Join(directory, "feedback.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{
		`{"schema_version":"v1","schema_version":"v1","entries":[]}`,
		`{"schema_version":"v1","entries":[],"unknown":true}`,
	} {
		if err := os.WriteFile(filepath.Join(directory, "feedback.json"), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Recent(); err == nil {
			t.Fatalf("unsafe document was accepted: %s", payload)
		}
	}
}
