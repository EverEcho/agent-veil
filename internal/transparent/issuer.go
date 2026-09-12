package transparent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
)

const maxCAPEMBytes = 64 << 10

func (c CA) IssueServerCertificate(scope Scope, sessionID string, process egress.ProcessIdentity, hostname string, now time.Time) (tls.Certificate, error) {
	hostname = canonicalHost(hostname)
	if now.IsZero() || !scope.Allows(sessionID, process, hostname) {
		return tls.Certificate{}, domain.NewError(domain.ErrInvalidContract, "issue transparent certificate", "session, process, or domain is outside the transparent scope")
	}
	certificatePEM, err := readCAFile(c.CertificatePath, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readCAFile(c.KeyPath, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clearBytes(keyPEM)
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return tls.Certificate{}, domain.NewError(domain.ErrInvalidContract, "issue transparent certificate", "CA material is invalid")
	}
	parent, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !parent.IsCA || now.Before(parent.NotBefore) || !now.Before(parent.NotAfter) {
		return tls.Certificate{}, domain.NewError(domain.ErrInvalidContract, "issue transparent certificate", "CA is invalid or expired")
	}
	signer, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !signer.PublicKey.Equal(parent.PublicKey) {
		return tls.Certificate{}, domain.NewError(domain.ErrInvalidContract, "issue transparent certificate", "CA key does not match certificate")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notAfter := now.Add(time.Hour)
	if parent.NotAfter.Before(notAfter) {
		notAfter = parent.NotAfter
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute), NotAfter: notAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return leaf, nil
}

func readCAFile(path string, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || private && before.Mode().Perm() != 0o600 || !private && before.Mode().Perm()&0o022 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "read transparent CA", "CA file permissions or type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, domain.NewError(domain.ErrInvalidContract, "read transparent CA", "CA file changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxCAPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxCAPEMBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "read transparent CA", "CA file is too large")
	}
	return payload, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
