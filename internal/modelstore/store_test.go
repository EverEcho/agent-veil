package modelstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func signedManifest(t *testing.T, private ed25519.PrivateKey, version string, payload []byte) Manifest {
	t.Helper()
	digest := sha256.Sum256(payload)
	manifest := Manifest{SchemaVersion: "v1", Version: version, Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, signingPayload(manifest)))
	return manifest
}

func TestStoreInstallsActivatesAndRollsBackVerifiedModels(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "1.1.0"} {
		payload := []byte("onnx-model-" + version)
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
	file, manifest, err := store.OpenActive()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payload, err := io.ReadAll(file)
	if err != nil || manifest.Version != "1.0.0" || string(payload) != "onnx-model-1.0.0" {
		t.Fatalf("manifest=%+v payload=%q err=%v", manifest, payload, err)
	}
	for _, path := range []string{filepath.Join(store.root, "active.json"), filepath.Join(store.root, "versions", "1.0.0", "model.onnx"), filepath.Join(store.root, "versions", "1.0.0", "manifest.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("path=%s mode=%v err=%v", path, info.Mode(), err)
		}
	}
}

func TestStoreRejectsBadSignatureSizeAndTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified-model")
	bad := signedManifest(t, private, "bad", payload)
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := store.Install(bad, bytes.NewReader(payload)); err == nil {
		t.Fatal("invalid signature was accepted")
	}
	oversized := signedManifest(t, private, "large", payload)
	oversized.Size = MaxArtifactBytes + 1
	oversized.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, signingPayload(oversized)))
	if err := store.Install(oversized, bytes.NewReader(payload)); err == nil {
		t.Fatal("oversized model was accepted")
	}
	manifest := signedManifest(t, private, "valid", payload)
	if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(store.root, "versions", "valid", "model.onnx")
	if err := os.WriteFile(artifact, []byte("tampered-model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Open("valid"); err == nil {
		t.Fatal("tampered installed model was accepted")
	}
	if _, err := store.List(); err == nil {
		t.Fatal("tampered installed model was omitted from inventory")
	}
}

func TestStoreRejectsUnsafeRootsAndVersions(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("relative/models", public); err == nil {
		t.Fatal("relative model root was accepted")
	}
	store, err := New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Open("../escape"); err == nil {
		t.Fatal("unsafe model version was accepted")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(store.root, "versions", "linked")); err == nil {
		if _, err := store.List(); err == nil {
			t.Fatal("symlinked model version was accepted by inventory")
		}
	}
}
