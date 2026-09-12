package transparent

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/egress"
)

func process(pid int, startedAt uint64) egress.ProcessIdentity {
	return egress.ProcessIdentity{ProcessID: pid, StartedAt: startedAt}
}

func TestScopeNeverInterceptsOutsideExactAllowlist(t *testing.T) {
	scope, err := NewScope("session", []egress.ProcessIdentity{process(42, 100)}, []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Allows("session", process(42, 100), "API.EXAMPLE.COM.") {
		t.Fatal("exact target rejected")
	}
	for _, check := range []bool{scope.Allows("other", process(42, 100), "api.example.com"), scope.Allows("session", process(43, 100), "api.example.com"), scope.Allows("session", process(42, 999), "api.example.com"), scope.Allows("session", process(42, 100), "evil.example.com"), scope.Allows("session", process(42, 100), "sub.api.example.com")} {
		if check {
			t.Fatal("out-of-scope interception allowed")
		}
	}
}

func TestScopeRejectsMalformedDomainsSessionsAndUnboundedSets(t *testing.T) {
	for _, value := range []string{".example.com", "example..com", "-api.example", "api-.example", "api example.com", "例子.example", "api.example:443", strings.Repeat("a", 64) + ".example"} {
		if _, err := NewScope("session", []egress.ProcessIdentity{process(1, 1)}, []string{value}); err == nil {
			t.Fatalf("malformed domain %q was accepted", value)
		}
	}
	if _, err := NewScope("session/escape", []egress.ProcessIdentity{process(1, 1)}, []string{"api.example"}); err == nil {
		t.Fatal("malformed session identity was accepted")
	}
	processes := make([]egress.ProcessIdentity, maxScopeProcesses+1)
	for index := range processes {
		processes[index] = process(index+1, uint64(index+1))
	}
	if _, err := NewScope("session", processes, []string{"api.example"}); err == nil {
		t.Fatal("unbounded process scope was accepted")
	}
	domains := make([]string, maxScopeDomains+1)
	for index := range domains {
		domains[index] = fmt.Sprintf("api-%d.example", index)
	}
	if _, err := NewScope("session", []egress.ProcessIdentity{process(1, 1)}, domains); err == nil {
		t.Fatal("unbounded domain scope was accepted")
	}
	if _, err := NewScope("session", []egress.ProcessIdentity{process(1, 1), process(1, 2)}, []string{"api.example"}); err == nil {
		t.Fatal("duplicate PID identities were accepted")
	}
}

func TestCALifecycleIsShortLivedAndRemovable(t *testing.T) {
	now := time.Now().UTC()
	ca, err := CreateCA(privateCARoot(t), now)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, _ := os.Stat(ca.KeyPath)
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("key mode=%o", keyInfo.Mode().Perm())
	}
	content, _ := os.ReadFile(ca.CertificatePath)
	block, _ := pem.Decode(content)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.IsCA || certificate.NotAfter.Sub(certificate.NotBefore) > 25*time.Hour {
		t.Fatal("CA is not session-scoped")
	}
	keyContent, err := os.ReadFile(ca.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyContent)
	if keyBlock == nil {
		t.Fatal("CA key is not PEM encoded")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || !privateKey.PublicKey.Equal(certificate.PublicKey) {
		t.Fatal("published CA certificate and private key do not match")
	}
	if err := ca.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := ca.Remove(); err != nil {
		t.Fatalf("idempotent removal failed: %v", err)
	}
	if _, err := os.Stat(ca.KeyPath); !os.IsNotExist(err) {
		t.Fatal("CA key was not removed")
	}
}

func TestCACreationPublishesIndependentAtomicDirectories(t *testing.T) {
	root := privateCARoot(t)
	now := time.Now().UTC()
	first, err := CreateCA(root, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateCA(root, now)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(first.KeyPath) == filepath.Dir(second.KeyPath) {
		t.Fatal("CA rotation overwrote the active key pair")
	}
	if err := first.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second.KeyPath); err != nil {
		t.Fatalf("removing old CA damaged replacement: %v", err)
	}
	if err := second.Remove(); err != nil {
		t.Fatal(err)
	}
}

func TestCARejectsRelativeAndUnsafeDirectories(t *testing.T) {
	if _, err := CreateCA("relative-ca", time.Now().UTC()); err == nil {
		t.Fatal("relative CA directory was accepted")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "linked")
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := CreateCA(root, time.Now().UTC()); err == nil {
		t.Fatal("symlinked CA directory was accepted")
	}
	fileRoot := filepath.Join(parent, "file")
	if err := os.WriteFile(fileRoot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(fileRoot, time.Now().UTC()); err == nil {
		t.Fatal("non-directory CA root was accepted")
	}
	wideRoot := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wideRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCA(wideRoot, time.Now().UTC()); err == nil {
		t.Fatal("group/world-readable CA root was accepted")
	}
}

func TestCreateCARejectsStoreAtCapacity(t *testing.T) {
	root := privateCARoot(t)
	for index := 0; index < maxStoredCAs; index++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("reserved-%04d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CreateCA(root, time.Now().UTC()); err == nil {
		t.Fatal("CA creation exceeded the store capacity")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxStoredCAs {
		t.Fatalf("capacity failure changed store entries: %d", len(entries))
	}
}

func TestConcurrentCreateCACannotExceedStoreCapacity(t *testing.T) {
	root := privateCARoot(t)
	for index := 0; index < maxStoredCAs-1; index++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("reserved-%04d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for index := 0; index < 2; index++ {
		go func(offset int) {
			ready.Done()
			<-start
			_, err := CreateCA(root, time.Now().UTC().Add(time.Duration(offset)*time.Second))
			results <- err
		}(index)
	}
	ready.Wait()
	close(start)
	succeeded := 0
	for index := 0; index < 2; index++ {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent CA creations=%d, want 1", succeeded)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxStoredCAs {
		t.Fatalf("store entries=%d, want %d", len(entries), maxStoredCAs)
	}
}

func TestCARemovalRejectsReplacedMaterialBeforeDeletingAnything(t *testing.T) {
	root := privateCARoot(t)
	ca, err := CreateCA(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	originalCertificate := ca.CertificatePath + ".original"
	if err := os.Rename(ca.CertificatePath, originalCertificate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca.CertificatePath, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ca.Remove(); err == nil {
		t.Fatal("replaced CA certificate was removed")
	}
	if _, err := os.Stat(ca.KeyPath); err != nil {
		t.Fatalf("valid key was deleted before replacement was detected: %v", err)
	}
	if content, err := os.ReadFile(ca.CertificatePath); err != nil || string(content) != "replacement" {
		t.Fatalf("replacement certificate changed: %q err=%v", content, err)
	}
}

func TestLoadCAsRecoversIndependentHandlesAfterRestart(t *testing.T) {
	root := privateCARoot(t)
	first, err := CreateCA(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateCA(root, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCAs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded[0].directory == loaded[1].directory {
		t.Fatalf("recovered CAs=%+v", loaded)
	}
	for _, ca := range loaded {
		if err := ca.Remove(); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.Remove(); err != nil {
		t.Fatalf("original first handle was not idempotent after recovery cleanup: %v", err)
	}
	if err := second.Remove(); err != nil {
		t.Fatalf("original second handle was not idempotent after recovery cleanup: %v", err)
	}
}

func TestLoadCAsFailsClosedOnMalformedMatchingDirectory(t *testing.T) {
	root := privateCARoot(t)
	malformed := filepath.Join(root, "ca-malformed")
	if err := os.Mkdir(malformed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malformed, "unexpected"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCAs(root); err == nil {
		t.Fatal("malformed CA directory was silently skipped")
	}
}

func privateCARoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "transparent")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
