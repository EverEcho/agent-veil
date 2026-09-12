package transparent

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func TestScopeNeverInterceptsOutsideExactAllowlist(t *testing.T) {
	scope, err := NewScope("session", []int{42}, []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Allows("session", 42, "API.EXAMPLE.COM.") {
		t.Fatal("exact target rejected")
	}
	for _, check := range []bool{scope.Allows("other", 42, "api.example.com"), scope.Allows("session", 43, "api.example.com"), scope.Allows("session", 42, "evil.example.com"), scope.Allows("session", 42, "sub.api.example.com")} {
		if check {
			t.Fatal("out-of-scope interception allowed")
		}
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
	if err := ca.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ca.KeyPath); !os.IsNotExist(err) {
		t.Fatal("CA key was not removed")
	}
}
