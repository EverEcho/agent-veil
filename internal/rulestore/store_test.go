package rulestore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
)

type gatedReader struct {
	reader           *bytes.Reader
	started, release chan struct{}
	once             sync.Once
}

func (r *gatedReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return r.reader.Read(buffer)
}

func signedManifest(t *testing.T, private ed25519.PrivateKey, version string, payload []byte) Manifest {
	t.Helper()
	manifest := Manifest{SchemaVersion: "v1", Version: version, Size: int64(len(payload)), SHA256: digest(payload)}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, SigningPayload(manifest)))
	return manifest
}

func rulePayload(t *testing.T, id string) []byte {
	t.Helper()
	payload, err := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: id, Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestStoreInstallsActivatesAndRollsBackVerifiedRulePacks(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "1.1.0"} {
		payload := rulePayload(t, "custom.ticket."+version)
		if err := store.Install(signedManifest(t, private, version, payload), bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	versions, err := store.List()
	if err != nil || len(versions) != 2 || versions[0].Version != "1.0.0" || versions[1].Version != "1.1.0" {
		t.Fatalf("verified versions=%+v err=%v", versions, err)
	}
	if err := store.Activate("1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatal(err)
	}
	pack, manifest, err := store.OpenActive()
	if err != nil || manifest.Version != "1.0.0" || pack.Rules[0].ID != "custom.ticket.1.0.0" {
		t.Fatalf("pack=%+v manifest=%+v err=%v", pack, manifest, err)
	}
	for _, path := range []string{filepath.Join(store.root, "active.json"), filepath.Join(store.root, "versions", "1.0.0", "rules.json"), filepath.Join(store.root, "versions", "1.0.0", "manifest.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("path=%s mode=%v err=%v", path, info.Mode(), err)
		}
	}
}

func TestStoreRejectsBadSignatureInvalidRulesAndTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload := rulePayload(t, "custom.ticket")
	bad := signedManifest(t, private, "bad", payload)
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := store.Install(bad, bytes.NewReader(payload)); err == nil {
		t.Fatal("invalid signature was accepted")
	}
	invalid := []byte(`{"schema_version":"v1","rules":[{"id":"pii.email","category":"custom.email","severity":"high","suggested_action":"redact","pattern":"x+"}]}`)
	if err := store.Install(signedManifest(t, private, "invalid", invalid), bytes.NewReader(invalid)); err == nil {
		t.Fatal("signed but invalid rule pack was accepted")
	}
	manifest := signedManifest(t, private, "valid", payload)
	if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(store.root, "versions", "valid", "rules.json")
	if err := os.WriteFile(artifact, []byte(`{"schema_version":"v1","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Open("valid"); err == nil {
		t.Fatal("tampered rule pack was accepted")
	}
	if _, err := store.List(); err == nil {
		t.Fatal("tampered rule pack was omitted from inventory")
	}
}

func TestStoreDeactivatesWithoutDeletingVerifiedRulePacks(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload := rulePayload(t, "custom.ticket")
	if err := store.Install(signedManifest(t, private, "1.0.0", payload), bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := store.Deactivate(); err != nil {
		t.Fatal(err)
	}
	if err := store.Deactivate(); err != nil {
		t.Fatalf("idempotent deactivation failed: %v", err)
	}
	if _, _, err := store.OpenActive(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deactivated rule pack remained active: %v", err)
	}
	versions, err := store.List()
	if err != nil || len(versions) != 1 || versions[0].Version != "1.0.0" {
		t.Fatalf("deactivation removed installed versions: versions=%+v error=%v", versions, err)
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatalf("verified rule pack could not be reactivated: %v", err)
	}
	pack, manifest, err := store.OpenActive()
	if err != nil || manifest.Version != "1.0.0" || len(pack.Rules) != 1 || pack.Rules[0].ID != "custom.ticket" {
		t.Fatalf("pack=%+v manifest=%+v error=%v", pack, manifest, err)
	}
}

func TestStoreRemovesOnlyVerifiedInactiveRulePacks(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "1.1.0"} {
		payload := rulePayload(t, "custom.ticket."+version)
		if err := store.Install(signedManifest(t, private, version, payload), bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Activate("1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("1.1.0"); err == nil {
		t.Fatal("active rule pack was removed")
	}
	extra := filepath.Join(store.root, "versions", "1.0.0", "unexpected")
	if err := os.WriteFile(extra, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("1.0.0"); err == nil {
		t.Fatal("malformed rule version was removed without surfacing its integrity failure")
	}
	if _, err := os.Stat(filepath.Join(store.root, "versions", "1.0.0", "manifest.json")); err != nil {
		t.Fatalf("failed removal damaged verified files: %v", err)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("1.0.0"); err != nil {
		t.Fatal(err)
	}
	versions, err := store.List()
	if err != nil || len(versions) != 1 || versions[0].Version != "1.1.0" {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}
	if _, _, err := store.Open("1.0.0"); err == nil {
		t.Fatalf("removed rule pack remains available: %v", err)
	}
	active, manifest, err := store.OpenActive()
	if err != nil || manifest.Version != "1.1.0" || len(active.Rules) != 1 {
		t.Fatalf("active=%+v manifest=%+v error=%v", active, manifest, err)
	}
}

func TestStoreRejectsUnsafeRootVersionAndAmbiguousJSON(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("relative/rules", public); err == nil {
		t.Fatal("relative rule root was accepted")
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Open("../escape"); err == nil {
		t.Fatal("unsafe rule version was accepted")
	}
	ambiguous := []byte(`{"schema_version":"v1","schema_version":"v1","rules":[]}`)
	if err := store.Install(signedManifest(t, private, "ambiguous", ambiguous), bytes.NewReader(ambiguous)); err == nil {
		t.Fatal("ambiguous signed JSON was accepted")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(store.root, "versions", "linked")); err == nil {
		if _, err := store.List(); err == nil {
			t.Fatal("symlinked rule version was accepted by inventory")
		}
	}
}

func TestStoreRejectsInstallAtVersionCapacity(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(store.root, "versions")
	for index := 0; index < maxInstalledVersions; index++ {
		if err := os.Mkdir(filepath.Join(versions, fmt.Sprintf("existing-%03d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	payload := rulePayload(t, "custom.overflow")
	if err := store.Install(signedManifest(t, private, "overflow", payload), bytes.NewReader(payload)); err == nil {
		t.Fatal("rule pack install exceeded version capacity")
	}
	if _, err := os.Lstat(filepath.Join(versions, "overflow")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("overflow version was partially installed: %v", err)
	}
}

func TestStoreInventoryCannotObservePartialInstall(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload := rulePayload(t, "custom.ticket")
	manifest := signedManifest(t, private, "1.0.0", payload)
	reader := &gatedReader{reader: bytes.NewReader(payload), started: make(chan struct{}), release: make(chan struct{})}
	installDone := make(chan error, 1)
	go func() { installDone <- store.Install(manifest, reader) }()
	<-reader.started
	listDone := make(chan error, 1)
	go func() {
		versions, err := store.List()
		if err == nil && (len(versions) != 1 || versions[0].Version != "1.0.0") {
			err = fmt.Errorf("inventory=%+v", versions)
		}
		listDone <- err
	}()
	select {
	case err := <-listDone:
		t.Fatalf("inventory observed an in-progress install: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	if err := <-installDone; err != nil {
		t.Fatal(err)
	}
	if err := <-listDone; err != nil {
		t.Fatal(err)
	}
}
