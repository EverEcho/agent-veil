//go:build linux

package transparent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type TrustReceipt struct {
	Fingerprint     string
	CertificatePath string
}

type TrustCommandRunner interface {
	Run(context.Context, string, ...string) error
}

type ExecTrustCommandRunner struct{}

func (ExecTrustCommandRunner) Run(ctx context.Context, executable string, args ...string) error {
	return exec.CommandContext(ctx, executable, args...).Run()
}

// LinuxTrustStore installs one exact AgentVeil CA into a distribution-managed
// certificate directory and refreshes the trust database without invoking a
// shell. The caller is responsible for obtaining the required OS privileges.
type LinuxTrustStore struct {
	root             string
	updateExecutable string
	updateArgs       []string
	runner           TrustCommandRunner
}

func NewLinuxTrustStore(root, updateExecutable string, updateArgs []string, runner TrustCommandRunner) (*LinuxTrustStore, error) {
	if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) || !filepath.IsAbs(updateExecutable) || strings.ContainsRune(updateExecutable, 0) || runner == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "create Linux trust store", "absolute trust paths and a command runner are required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create Linux trust store", "trust directory permissions or type are unsafe")
	}
	args := append([]string(nil), updateArgs...)
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return nil, domain.NewError(domain.ErrInvalidContract, "create Linux trust store", "trust refresh argument is unsafe")
		}
	}
	return &LinuxTrustStore{root: root, updateExecutable: updateExecutable, updateArgs: args, runner: runner}, nil
}

func (s *LinuxTrustStore) Install(ctx context.Context, ca CA) (TrustReceipt, error) {
	if s == nil || ctx == nil {
		return TrustReceipt{}, domain.NewError(domain.ErrInvalidContract, "install Linux trust", "trust store and context are required")
	}
	payload, fingerprint, err := trustedCAPayload(ca)
	if err != nil {
		return TrustReceipt{}, err
	}
	target := filepath.Join(s.root, "agentveil-"+fingerprint+".crt")
	receipt := TrustReceipt{Fingerprint: fingerprint, CertificatePath: target}
	if existing, err := readTrustedCertificate(target); err == nil {
		if existingFingerprint, fingerprintErr := certificateFingerprint(existing); fingerprintErr != nil || existingFingerprint != fingerprint {
			return TrustReceipt{}, domain.NewError(domain.ErrInvalidContract, "install Linux trust", "trust target contains different material")
		}
		if err := s.refresh(ctx); err != nil {
			return TrustReceipt{}, domain.NewError(domain.ErrInvalidContract, "install Linux trust", "existing trust target could not be refreshed")
		}
		return receipt, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return TrustReceipt{}, err
	}
	if err := writeTrustedCertificateAtomic(target, payload); err != nil {
		return TrustReceipt{}, err
	}
	if err := s.refresh(ctx); err != nil {
		rollbackErr := removeTrustedCertificate(target, fingerprint)
		if rollbackErr == nil {
			rollbackErr = s.refresh(ctx)
		}
		if rollbackErr != nil {
			return TrustReceipt{}, domain.NewError(domain.ErrInvalidContract, "install Linux trust", "trust refresh and rollback failed")
		}
		return TrustReceipt{}, domain.NewError(domain.ErrInvalidContract, "install Linux trust", "trust refresh failed and installation was rolled back")
	}
	return receipt, nil
}

func (s *LinuxTrustStore) Uninstall(ctx context.Context, receipt TrustReceipt) error {
	if s == nil || ctx == nil || !validFingerprint(receipt.Fingerprint) {
		return domain.NewError(domain.ErrInvalidContract, "uninstall Linux trust", "trust store, context, and receipt are required")
	}
	expected := filepath.Join(s.root, "agentveil-"+receipt.Fingerprint+".crt")
	if receipt.CertificatePath != expected {
		return domain.NewError(domain.ErrInvalidContract, "uninstall Linux trust", "trust receipt path is invalid")
	}
	payload, err := readTrustedCertificate(expected)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	fingerprint, err := certificateFingerprint(payload)
	if err != nil || fingerprint != receipt.Fingerprint {
		return domain.NewError(domain.ErrInvalidContract, "uninstall Linux trust", "trusted certificate no longer matches its receipt")
	}
	if err := os.Remove(expected); err != nil {
		return err
	}
	if err := syncCADirectory(s.root); err != nil {
		_ = writeTrustedCertificateAtomic(expected, payload)
		return err
	}
	if err := s.refresh(ctx); err != nil {
		if restoreErr := writeTrustedCertificateAtomic(expected, payload); restoreErr != nil {
			return domain.NewError(domain.ErrInvalidContract, "uninstall Linux trust", "trust refresh failed and certificate restoration failed")
		}
		if restoreErr := s.refresh(ctx); restoreErr != nil {
			return domain.NewError(domain.ErrInvalidContract, "uninstall Linux trust", "trust refresh failed and restored state could not be refreshed")
		}
		return domain.NewError(domain.ErrInvalidContract, "uninstall Linux trust", "trust refresh failed and certificate was restored")
	}
	return nil
}

func (s *LinuxTrustStore) Receipt(ca CA) (TrustReceipt, error) {
	if s == nil {
		return TrustReceipt{}, domain.NewError(domain.ErrInvalidContract, "create Linux trust receipt", "trust store is unavailable")
	}
	_, fingerprint, err := trustedCAPayload(ca)
	if err != nil {
		return TrustReceipt{}, err
	}
	return TrustReceipt{Fingerprint: fingerprint, CertificatePath: filepath.Join(s.root, "agentveil-"+fingerprint+".crt")}, nil
}

func (s *LinuxTrustStore) refresh(ctx context.Context) error {
	return s.runner.Run(ctx, s.updateExecutable, s.updateArgs...)
}

func trustedCAPayload(ca CA) ([]byte, string, error) {
	opened, err := OpenCA(ca.directory)
	if err != nil {
		return nil, "", err
	}
	for _, identity := range []struct {
		path     string
		expected os.FileInfo
	}{{opened.directory, ca.directoryInfo}, {opened.CertificatePath, ca.certificateInfo}, {opened.KeyPath, ca.keyInfo}} {
		matches, err := sameCAFile(identity.path, identity.expected)
		if err != nil || !matches {
			return nil, "", domain.NewError(domain.ErrInvalidContract, "install Linux trust", "CA identity changed after creation")
		}
	}
	payload, err := readCAFile(opened.CertificatePath, false)
	if err != nil {
		return nil, "", err
	}
	fingerprint, err := certificateFingerprint(payload)
	return payload, fingerprint, err
}

func certificateFingerprint(payload []byte) (string, error) {
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", domain.NewError(domain.ErrInvalidContract, "fingerprint transparent CA", "certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		return "", domain.NewError(domain.ErrInvalidContract, "fingerprint transparent CA", "certificate is not a valid CA")
	}
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:]), nil
}

func readTrustedCertificate(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "read Linux trust", "trusted certificate permissions or type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, domain.NewError(domain.ErrInvalidContract, "read Linux trust", "trusted certificate changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxCAPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxCAPEMBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "read Linux trust", "trusted certificate is too large")
	}
	return payload, nil
}

func writeTrustedCertificateAtomic(path string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".agentveil-trust-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return domain.NewError(domain.ErrInvalidContract, "write Linux trust", "trust target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncCADirectory(filepath.Dir(path))
}

func removeTrustedCertificate(path, fingerprint string) error {
	payload, err := readTrustedCertificate(path)
	if err != nil {
		return err
	}
	actual, err := certificateFingerprint(payload)
	if err != nil || actual != fingerprint {
		return domain.NewError(domain.ErrInvalidContract, "remove Linux trust", "trust target identity changed")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncCADirectory(filepath.Dir(path))
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
