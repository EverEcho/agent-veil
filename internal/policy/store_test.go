package policy

import (
	"context"
	"github.com/agentveil/agentveil/internal/domain"
	"os"
	"path/filepath"
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
			id = ids[0]
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
