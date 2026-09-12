package transparent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CA struct{ CertificatePath, KeyPath string }

func CreateCA(directory string, now time.Time) (CA, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return CA{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CA{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return CA{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "AgentVeil Session CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, MaxPathLenZero: true}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return CA{}, err
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CA{}, err
	}
	ca := CA{CertificatePath: filepath.Join(directory, "ca-cert.pem"), KeyPath: filepath.Join(directory, "ca-key.pem")}
	if err := atomicWrite(ca.CertificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0644); err != nil {
		return CA{}, err
	}
	if err := atomicWrite(ca.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0600); err != nil {
		_ = os.Remove(ca.CertificatePath)
		return CA{}, err
	}
	return ca, nil
}

func (c CA) Remove() error {
	if err := os.Remove(c.KeyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(c.CertificatePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
func atomicWrite(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
