package transparent

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	ca, err := CreateCA(t.TempDir(), now)
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
	root := filepath.Join(t.TempDir(), "transparent")
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
}
