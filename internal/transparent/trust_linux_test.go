//go:build linux

package transparent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type recordingTrustRunner struct {
	calls          int
	fail           map[int]error
	lastExecutable string
	lastArgs       []string
	hadDeadline    bool
}

func (r *recordingTrustRunner) Run(ctx context.Context, executable string, args ...string) error {
	r.calls++
	r.lastExecutable = executable
	r.lastArgs = append([]string(nil), args...)
	_, r.hadDeadline = ctx.Deadline()
	return r.fail[r.calls]
}

func TestLinuxTrustStoreInstallsRefreshesAndUninstallsExactCA(t *testing.T) {
	ca, err := CreateCA(privateCARoot(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	trustRoot := linuxTrustRoot(t)
	runner := &recordingTrustRunner{}
	store, err := NewLinuxTrustStore(trustRoot, "/usr/sbin/update-ca-certificates", []string{"--fresh"}, runner)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Install(context.Background(), ca)
	if err != nil {
		t.Fatal(err)
	}
	if !validFingerprint(receipt.Fingerprint) || filepath.Dir(receipt.CertificatePath) != trustRoot || runner.calls != 1 || runner.lastExecutable != "/usr/sbin/update-ca-certificates" || len(runner.lastArgs) != 1 || runner.lastArgs[0] != "--fresh" || !runner.hadDeadline {
		t.Fatalf("receipt=%+v refresh calls=%d", receipt, runner.calls)
	}
	info, err := os.Stat(receipt.CertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("trusted certificate mode=%v", info.Mode().Perm())
	}
	second, err := store.Install(context.Background(), ca)
	if err != nil || second != receipt || runner.calls != 2 {
		t.Fatalf("idempotent install=%+v calls=%d err=%v", second, runner.calls, err)
	}
	if err := store.Uninstall(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 3 {
		t.Fatalf("refresh calls=%d", runner.calls)
	}
	if _, err := os.Stat(receipt.CertificatePath); !os.IsNotExist(err) {
		t.Fatalf("trusted certificate survived uninstall: %v", err)
	}
	if err := store.Uninstall(context.Background(), receipt); err != nil {
		t.Fatalf("idempotent uninstall failed: %v", err)
	}
	if runner.calls != 4 {
		t.Fatalf("idempotent uninstall did not reconcile trust database: calls=%d", runner.calls)
	}
}

func TestLinuxTrustStoreMissingCertificateStillReconcilesTrustDatabase(t *testing.T) {
	ca, err := CreateCA(privateCARoot(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	runner := &recordingTrustRunner{fail: map[int]error{1: errors.New("refresh failed")}}
	store, err := NewLinuxTrustStore(linuxTrustRoot(t), "/usr/sbin/update-ca-certificates", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Receipt(ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Uninstall(context.Background(), receipt); err == nil || runner.calls != 1 {
		t.Fatalf("missing certificate reconciliation calls=%d error=%v", runner.calls, err)
	}
	delete(runner.fail, 1)
	if err := store.Uninstall(context.Background(), receipt); err != nil || runner.calls != 2 {
		t.Fatalf("missing certificate retry calls=%d error=%v", runner.calls, err)
	}
}

func TestLinuxTrustStoreRollsBackFailedInstallRefresh(t *testing.T) {
	ca, err := CreateCA(privateCARoot(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	runner := &recordingTrustRunner{fail: map[int]error{1: errors.New("refresh failed")}}
	store, err := NewLinuxTrustStore(linuxTrustRoot(t), "/usr/sbin/update-ca-certificates", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Install(context.Background(), ca)
	if err == nil || receipt != (TrustReceipt{}) || runner.calls != 2 {
		t.Fatalf("receipt=%+v calls=%d err=%v", receipt, runner.calls, err)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed install left trust files: %+v err=%v", entries, err)
	}
}

func TestLinuxTrustStoreRestoresCertificateWhenUninstallRefreshFails(t *testing.T) {
	ca, err := CreateCA(privateCARoot(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	runner := &recordingTrustRunner{}
	store, err := NewLinuxTrustStore(linuxTrustRoot(t), "/usr/sbin/update-ca-certificates", nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Install(context.Background(), ca)
	if err != nil {
		t.Fatal(err)
	}
	runner.fail = map[int]error{2: errors.New("refresh failed")}
	if err := store.Uninstall(context.Background(), receipt); err == nil {
		t.Fatal("failed trust refresh was reported as successful")
	}
	if runner.calls != 3 {
		t.Fatalf("refresh calls=%d", runner.calls)
	}
	payload, err := readTrustedCertificate(receipt.CertificatePath)
	if err != nil {
		t.Fatalf("certificate was not restored: %v", err)
	}
	if fingerprint, err := certificateFingerprint(payload); err != nil || fingerprint != receipt.Fingerprint {
		t.Fatalf("restored fingerprint=%q err=%v", fingerprint, err)
	}
}

func TestLinuxTrustStoreRejectsReplacedCertificateAndUnsafeConfiguration(t *testing.T) {
	ca, err := CreateCA(privateCARoot(t), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	root := linuxTrustRoot(t)
	store, err := NewLinuxTrustStore(root, "/usr/sbin/update-ca-certificates", nil, &recordingTrustRunner{})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Install(context.Background(), ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt.CertificatePath, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Uninstall(context.Background(), receipt); err == nil {
		t.Fatal("replacement trust material was deleted")
	}
	if content, err := os.ReadFile(receipt.CertificatePath); err != nil || string(content) != "replacement" {
		t.Fatalf("replacement changed: %q err=%v", content, err)
	}
	if _, err := NewLinuxTrustStore("relative", "/usr/sbin/update-ca-certificates", nil, &recordingTrustRunner{}); err == nil {
		t.Fatal("relative trust root was accepted")
	}
	if _, err := NewLinuxTrustStore(root, "update-ca-certificates", nil, &recordingTrustRunner{}); err == nil {
		t.Fatal("PATH-resolved refresh command was accepted")
	}
}

func linuxTrustRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "anchors")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}
