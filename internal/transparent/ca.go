package transparent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type CA struct {
	CertificatePath string
	KeyPath         string
	directory       string
	directoryInfo   os.FileInfo
	certificateInfo os.FileInfo
	keyInfo         os.FileInfo
}

func CreateCA(directory string, now time.Time) (CA, error) {
	if directory == "" || !filepath.IsAbs(directory) || now.IsZero() {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "create transparent CA", "absolute directory and creation time are required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return CA{}, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "create transparent CA", "CA directory permissions or type are unsafe")
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
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "AgentVeil Session CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, MaxPathLen: 0, MaxPathLenZero: true}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return CA{}, err
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CA{}, err
	}
	staging, err := os.MkdirTemp(directory, ".ca-stage-*")
	if err != nil {
		return CA{}, err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return CA{}, err
	}
	if err := writeCAFile(filepath.Join(staging, "ca-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o644); err != nil {
		return CA{}, err
	}
	if err := writeCAFile(filepath.Join(staging, "ca-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600); err != nil {
		return CA{}, err
	}
	if err := syncCADirectory(staging); err != nil {
		return CA{}, err
	}
	finalDirectory := filepath.Join(directory, "ca-"+serial.Text(16))
	if err := os.Rename(staging, finalDirectory); err != nil {
		return CA{}, err
	}
	if err := syncCADirectory(directory); err != nil {
		_ = os.Remove(filepath.Join(finalDirectory, "ca-key.pem"))
		_ = os.Remove(filepath.Join(finalDirectory, "ca-cert.pem"))
		_ = os.Remove(finalDirectory)
		return CA{}, err
	}
	certificatePath := filepath.Join(finalDirectory, "ca-cert.pem")
	keyPath := filepath.Join(finalDirectory, "ca-key.pem")
	directoryInfo, directoryErr := os.Lstat(finalDirectory)
	certificateInfo, certificateErr := os.Lstat(certificatePath)
	keyInfo, keyErr := os.Lstat(keyPath)
	if directoryErr != nil || certificateErr != nil || keyErr != nil {
		_ = os.Remove(keyPath)
		_ = os.Remove(certificatePath)
		_ = os.Remove(finalDirectory)
		return CA{}, domain.NewError(domain.ErrInvalidContract, "create transparent CA", "published CA identity could not be verified")
	}
	return CA{CertificatePath: certificatePath, KeyPath: keyPath, directory: finalDirectory, directoryInfo: directoryInfo, certificateInfo: certificateInfo, keyInfo: keyInfo}, nil
}

func (c CA) Remove() error {
	if c.directory == "" || !filepath.IsAbs(c.directory) || !strings.HasPrefix(filepath.Base(c.directory), "ca-") || c.CertificatePath != filepath.Join(c.directory, "ca-cert.pem") || c.KeyPath != filepath.Join(c.directory, "ca-key.pem") || c.directoryInfo == nil || c.certificateInfo == nil || c.keyInfo == nil {
		return domain.NewError(domain.ErrInvalidContract, "remove transparent CA", "CA paths are invalid")
	}
	directoryExists, err := sameCAFile(c.directory, c.directoryInfo)
	if err != nil {
		return err
	}
	certificateExists, err := sameCAFile(c.CertificatePath, c.certificateInfo)
	if err != nil {
		return err
	}
	keyExists, err := sameCAFile(c.KeyPath, c.keyInfo)
	if err != nil {
		return err
	}
	if !directoryExists {
		if certificateExists || keyExists {
			return domain.NewError(domain.ErrInvalidContract, "remove transparent CA", "CA directory identity is missing")
		}
		return nil
	}
	for _, path := range []string{c.KeyPath, c.CertificatePath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(c.directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(c.directory)
	if _, err := os.Stat(parent); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return syncCADirectory(parent)
}

func sameCAFile(path string, expected os.FileInfo) (bool, error) {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !os.SameFile(current, expected) {
		return false, domain.NewError(domain.ErrInvalidContract, "remove transparent CA", "CA material changed after creation")
	}
	return true, nil
}

func writeCAFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncCADirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
