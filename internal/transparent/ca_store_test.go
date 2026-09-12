package transparent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAStoreActivatesRotatesAndRevokesLocally(t *testing.T) {
	root := privateCARoot(t)
	store, err := NewCAStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Active(); err != nil || ok {
		t.Fatalf("empty store active=%v err=%v", ok, err)
	}
	first, err := CreateCA(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(first); err != nil {
		t.Fatal(err)
	}
	store, err = NewCAStore(root)
	if err != nil {
		t.Fatal(err)
	}
	active, ok, err := store.Active()
	if err != nil || !ok || active.CertificatePath != first.CertificatePath {
		t.Fatalf("first active=%+v ok=%v err=%v", active, ok, err)
	}
	stateInfo, err := os.Stat(filepath.Join(root, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("active state mode=%v", stateInfo.Mode().Perm())
	}

	second, err := CreateCA(root, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(second); err != nil {
		t.Fatal(err)
	}
	active, ok, err = store.Active()
	if err != nil || !ok || active.CertificatePath != second.CertificatePath {
		t.Fatalf("rotated active=%+v ok=%v err=%v", active, ok, err)
	}
	if _, err := os.Stat(first.KeyPath); err != nil {
		t.Fatalf("rotation removed previous CA before trust retirement: %v", err)
	}
	revoked, err := store.RevokeActive()
	if err != nil || !revoked {
		t.Fatalf("revoked=%v err=%v", revoked, err)
	}
	if _, ok, err := store.Active(); err != nil || ok {
		t.Fatalf("revoked store active=%v err=%v", ok, err)
	}
	if _, err := os.Stat(second.KeyPath); !os.IsNotExist(err) {
		t.Fatalf("revoked private key remains: %v", err)
	}
	if err := first.Remove(); err != nil {
		t.Fatal(err)
	}
}

func TestCAStoreRejectsForeignAndAmbiguousState(t *testing.T) {
	root := privateCARoot(t)
	store, err := NewCAStore(root)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := CreateCA(privateCARoot(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Remove()
	if err := store.Activate(foreign); err == nil {
		t.Fatal("foreign CA was activated")
	}
	state := []byte(`{"schema_version":"v1","schema_version":"v1","directory":"ca-1"}` + "\n")
	if err := os.WriteFile(filepath.Join(root, "active.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Active(); err == nil {
		t.Fatal("ambiguous active state was accepted")
	}
}

func TestCAStoreRejectsWideOrRelativeRoots(t *testing.T) {
	if _, err := NewCAStore("relative"); err == nil {
		t.Fatal("relative CA store was accepted")
	}
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCAStore(wide); err == nil {
		t.Fatal("wide CA store permissions were accepted")
	}
}

func TestOpenCARejectsCorruptedMaterialBeforeActivation(t *testing.T) {
	root := privateCARoot(t)
	ca, err := CreateCA(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca.CertificatePath, []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCA(filepath.Dir(ca.CertificatePath)); err == nil {
		t.Fatal("corrupted CA material was reopened")
	}
	store, err := NewCAStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(ca); err == nil {
		t.Fatal("corrupted CA material was activated")
	}
}
