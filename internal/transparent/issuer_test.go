package transparent

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func TestIssuerRestrictsLeafCertificatesToExactScope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := CreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	scope, err := NewScope("session-a", []int{42}, []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		session string
		pid     int
		host    string
	}{
		{"session-b", 42, "api.example.com"},
		{"session-a", 43, "api.example.com"},
		{"session-a", 42, "sub.api.example.com"},
		{"session-a", 42, "127.0.0.1"},
	} {
		if _, err := ca.IssueServerCertificate(scope, request.session, request.pid, request.host, now); err == nil {
			t.Fatalf("out-of-scope certificate was issued: %+v", request)
		}
	}
	leaf, err := ca.IssueServerCertificate(scope, "session-a", 42, "API.EXAMPLE.COM.", now)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf == nil || leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore) > time.Hour+time.Minute || len(leaf.Leaf.DNSNames) != 1 || leaf.Leaf.DNSNames[0] != "api.example.com" {
		t.Fatalf("leaf=%+v", leaf.Leaf)
	}
	rootPEM, err := os.ReadFile(ca.CertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: pool, CurrentTime: now}); err != nil {
		t.Fatalf("issued leaf did not verify: %v", err)
	}
}

func TestIssuerRejectsTamperedCAPermissions(t *testing.T) {
	now := time.Now().UTC()
	ca, err := CreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Remove()
	if err := os.Chmod(ca.KeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	scope, _ := NewScope("session", []int{1}, []string{"api.example.com"})
	if _, err := ca.IssueServerCertificate(scope, "session", 1, "api.example.com", now); err == nil {
		t.Fatal("unsafe CA key permissions were accepted")
	}
}
