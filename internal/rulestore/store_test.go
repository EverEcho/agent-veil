package rulestore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
)

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
}
