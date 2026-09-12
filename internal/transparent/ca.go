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
	"sort"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

const maxStoredCAs = 1024

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
	created, err := OpenCA(finalDirectory)
	if err != nil {
		_ = os.Remove(filepath.Join(finalDirectory, "ca-key.pem"))
		_ = os.Remove(filepath.Join(finalDirectory, "ca-cert.pem"))
		_ = os.Remove(finalDirectory)
		return CA{}, domain.NewError(domain.ErrInvalidContract, "create transparent CA", "published CA identity could not be verified")
	}
	return created, nil
}

// OpenCA reconstructs a removable CA handle after a process restart. It only
// accepts an exact private CA directory created by AgentVeil.
func OpenCA(directory string) (CA, error) {
	if !validCADirectoryPath(directory) {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "open transparent CA", "CA directory path is invalid")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "open transparent CA", "CA directory permissions or type are unsafe")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 || entries[0].Name() != "ca-cert.pem" || entries[1].Name() != "ca-key.pem" {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "open transparent CA", "CA directory contents are invalid")
	}
	certificatePath := filepath.Join(directory, "ca-cert.pem")
	keyPath := filepath.Join(directory, "ca-key.pem")
	certificateInfo, certificateErr := os.Lstat(certificatePath)
	keyInfo, keyErr := os.Lstat(keyPath)
	if certificateErr != nil || keyErr != nil || !certificateInfo.Mode().IsRegular() || certificateInfo.Mode().Perm()&0o022 != 0 || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm() != 0o600 {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "open transparent CA", "CA material permissions or type are unsafe")
	}
	return CA{CertificatePath: certificatePath, KeyPath: keyPath, directory: directory, directoryInfo: directoryInfo, certificateInfo: certificateInfo, keyInfo: keyInfo}, nil
}

// LoadCAs returns every recoverable CA beneath a private store root. Matching
// but malformed entries fail closed so crash cleanup cannot silently skip
// attacker-replaced material.
func LoadCAs(root string) ([]CA, error) {
	if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) {
		return nil, domain.NewError(domain.ErrInvalidContract, "load transparent CAs", "CA root path is invalid")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "load transparent CAs", "CA root permissions or type are unsafe")
	}
	directory, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maxStoredCAs + 1)
	closeErr := directory.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maxStoredCAs {
		return nil, domain.NewError(domain.ErrInvalidContract, "load transparent CAs", "CA store contains too many entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	result := make([]CA, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "ca-") {
			continue
		}
		ca, err := OpenCA(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		result = append(result, ca)
	}
	return result, nil
}

func (c CA) Remove() error {
	if !validCADirectoryPath(c.directory) || c.CertificatePath != filepath.Join(c.directory, "ca-cert.pem") || c.KeyPath != filepath.Join(c.directory, "ca-key.pem") || c.directoryInfo == nil || c.certificateInfo == nil || c.keyInfo == nil {
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

func validCADirectoryPath(directory string) bool {
	return directory != "" && filepath.IsAbs(directory) && !strings.ContainsRune(directory, 0) && strings.HasPrefix(filepath.Base(directory), "ca-")
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
