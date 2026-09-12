//go:build linux

package transparent

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLinuxCAControllerCompletesRotationAndRevocation(t *testing.T) {
	material, err := NewCAStore(privateCARoot(t))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewLinuxTrustStore(linuxTrustRoot(t), "/usr/sbin/update-ca-certificates", nil, &recordingTrustRunner{})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewLinuxCAController(material, trust)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := controller.Rotate(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.Rotate(ctx, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.directory == second.directory {
		t.Fatal("rotation reused CA material")
	}
	if _, err := os.Stat(first.KeyPath); !os.IsNotExist(err) {
		t.Fatalf("retired private key remains: %v", err)
	}
	assertCAStoreCounts(t, material, trust, 1, 1)
	active, ok, err := material.Active()
	if err != nil || !ok || active.directory != second.directory {
		t.Fatalf("active=%+v ok=%v err=%v", active, ok, err)
	}
	revoked, err := controller.Revoke(ctx)
	if err != nil || !revoked {
		t.Fatalf("revoked=%v err=%v", revoked, err)
	}
	assertCAStoreCounts(t, material, trust, 0, 0)
	if _, ok, err := material.Active(); err != nil || ok {
		t.Fatalf("revoked material active=%v err=%v", ok, err)
	}
	if revoked, err := controller.Revoke(ctx); err != nil || revoked {
		t.Fatalf("idempotent revoke=%v err=%v", revoked, err)
	}
}

func TestLinuxCAControllerReconcilesInterruptedRotationStates(t *testing.T) {
	material, err := NewCAStore(privateCARoot(t))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewLinuxTrustStore(linuxTrustRoot(t), "/usr/sbin/update-ca-certificates", nil, &recordingTrustRunner{})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewLinuxCAController(material, trust)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := controller.Rotate(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	staged, err := CreateCA(material.root, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Install(ctx, staged); err != nil {
		t.Fatal(err)
	}
	assertCAStoreCounts(t, material, trust, 2, 2)
	if err := controller.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	assertCAStoreCounts(t, material, trust, 1, 1)
	if _, err := os.Stat(staged.KeyPath); !os.IsNotExist(err) {
		t.Fatalf("unactivated staged key survived reconciliation: %v", err)
	}

	activated, err := CreateCA(material.root, time.Now().UTC().Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Install(ctx, activated); err != nil {
		t.Fatal(err)
	}
	if err := material.Activate(activated); err != nil {
		t.Fatal(err)
	}
	assertCAStoreCounts(t, material, trust, 2, 2)
	if err := controller.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	assertCAStoreCounts(t, material, trust, 1, 1)
	if _, err := os.Stat(first.KeyPath); !os.IsNotExist(err) {
		t.Fatalf("previous active key survived reconciliation: %v", err)
	}
	active, ok, err := material.Active()
	if err != nil || !ok || active.directory != activated.directory {
		t.Fatalf("active=%+v ok=%v err=%v", active, ok, err)
	}
}

func assertCAStoreCounts(t *testing.T, material *CAStore, trust *LinuxTrustStore, wantMaterial, wantTrust int) {
	t.Helper()
	cas, err := LoadCAs(material.root)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(trust.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != wantMaterial || len(entries) != wantTrust {
		t.Fatalf("material=%d want=%d trust=%d want=%d", len(cas), wantMaterial, len(entries), wantTrust)
	}
}
