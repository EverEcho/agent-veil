package policy

import (
	"context"
	"errors"
	"fmt"
	"github.com/agentveil/agentveil/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyStoreRoundTripAndPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "policy.json")
	store, _ := NewStore(path)
	document := Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: []Rule{{Scope: Scope{FindingType: "secret.private_key"}, Action: domain.ActionBlock}}}
	if err := store.Save(document); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Rules) != 1 {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestPolicyStoreRejectsRelativeUnsafeAndOversizedFiles(t *testing.T) {
	if _, err := NewStore("relative/policy.json"); err == nil {
		t.Fatal("relative policy path was accepted")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "policy.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"schema_version":"v1","default":"redact","rules":[]}`
	if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("world-readable policy file was accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxPolicyBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("oversized policy file was accepted")
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("symlinked policy file was accepted")
	}
}

func TestPolicyStoreRejectsUnsafeDirectoryAndOversizedSave(t *testing.T) {
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Join(wide, "policy.json")); err == nil {
		t.Fatal("world-accessible policy directory was accepted")
	}
	store, err := NewStore(filepath.Join(t.TempDir(), "private", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules := make([]Rule, maxPolicyRules+1)
	for index := range rules {
		rules[index] = Rule{Scope: Scope{AgentID: fmt.Sprintf("agent-%d", index)}, Action: domain.ActionBlock}
	}
	if err := store.Save(Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: rules}); err == nil {
		t.Fatal("oversized policy rule set was saved")
	}
	largeRules := make([]Rule, maxPolicyRules)
	longSurface := "surface-" + strings.Repeat("s", 110)
	longFinding := "finding-" + strings.Repeat("f", 110)
	longProvider := strings.Repeat("p", 60) + "." + strings.Repeat("q", 60) + "." + strings.Repeat("r", 60) + "." + strings.Repeat("s", 60)
	for index := range largeRules {
		largeRules[index] = Rule{Scope: Scope{AgentID: fmt.Sprintf("%s%04d", strings.Repeat("a", 110), index), SurfaceID: longSurface, FindingType: longFinding, Provider: longProvider}, Action: domain.ActionBlock}
	}
	if err := store.Save(Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: largeRules}); err == nil {
		t.Fatal("oversized serialized policy was saved")
	}
}

func TestPolicyStoreRejectsDuplicateKeys(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "policy.json")
	payload := `{"schema_version":"v1","default":"redact","default":"allow","rules":[]}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("policy with duplicate action was accepted")
	}
}

func TestASKBrokerIsOneTimeAndFailsClosedOnTimeout(t *testing.T) {
	broker := NewBroker()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if action, err := broker.Request(ctx, domain.Finding{}); err == nil || action != domain.ActionBlock {
		t.Fatal("timeout did not block")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan domain.Action)
	go func() { action, _ := broker.Request(ctx, domain.Finding{}); result <- action }()
	var id string
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		ids := broker.Pending()
		if len(ids) > 0 {
			id = ids[0].ID
			break
		}
	}
	if id == "" || !broker.Resolve(id, domain.ActionAllow) {
		t.Fatal("approval unavailable")
	}
	if <-result != domain.ActionAllow || broker.Resolve(id, domain.ActionAllow) {
		t.Fatal("approval was not one-time")
	}
}

func TestASKBrokerFailsClosedAtPendingCapacity(t *testing.T) {
	broker := NewBroker()
	for index := 0; index < maxPendingApprovals; index++ {
		broker.pending[fmt.Sprintf("%032d", index)] = pendingApproval{channel: make(chan approvalResult, 1)}
	}
	action, err := broker.Request(context.Background(), domain.Finding{})
	var veilErr *domain.VeilError
	if action != domain.ActionBlock || !errors.As(err, &veilErr) || veilErr.Code != domain.ErrInteractionRequired || len(broker.pending) != maxPendingApprovals {
		t.Fatalf("action=%s pending=%d err=%v", action, len(broker.pending), err)
	}
	approvals := broker.Pending()
	for index := 1; index < len(approvals); index++ {
		if approvals[index-1].ID >= approvals[index].ID {
			t.Fatal("pending approvals are not deterministically sorted")
		}
	}
}
