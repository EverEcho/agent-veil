package transparent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const maxCAStateBytes = 4096

type caState struct {
	SchemaVersion string `json:"schema_version"`
	Directory     string `json:"directory"`
}

// CAStore owns the local active-CA pointer. Operating-system trust-store
// installation remains a separate privileged step; activation here only makes
// a staged key eligible for signing inside AgentVeil.
type CAStore struct {
	root string
	mu   sync.Mutex
}

func NewCAStore(root string) (*CAStore, error) {
	if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) {
		return nil, domain.NewError(domain.ErrInvalidContract, "create CA store", "CA root path is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create CA store", "CA root permissions or type are unsafe")
	}
	return &CAStore{root: root}, nil
}

func (s *CAStore) Activate(candidate CA) error {
	if s == nil {
		return domain.NewError(domain.ErrInvalidContract, "activate transparent CA", "CA store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.validateCandidate(candidate)
	if err != nil {
		return err
	}
	state := caState{SchemaVersion: "v1", Directory: filepath.Base(current.directory)}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeCAStateAtomic(filepath.Join(s.root, "active.json"), append(payload, '\n'))
}

func (s *CAStore) Active() (CA, bool, error) {
	if s == nil {
		return CA{}, false, domain.NewError(domain.ErrInvalidContract, "open active transparent CA", "CA store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked()
}

// RevokeActive removes signing eligibility before deleting the active private
// key. Trust-store removal must be completed by the platform adapter.
func (s *CAStore) RevokeActive() (bool, error) {
	if s == nil {
		return false, domain.NewError(domain.ErrInvalidContract, "revoke transparent CA", "CA store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active, ok, err := s.activeLocked()
	if err != nil || !ok {
		return false, err
	}
	if err := removeCAState(filepath.Join(s.root, "active.json"), s.root); err != nil {
		return false, err
	}
	if err := active.Remove(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *CAStore) activeLocked() (CA, bool, error) {
	payload, err := readCAState(filepath.Join(s.root, "active.json"))
	if errors.Is(err, os.ErrNotExist) {
		return CA{}, false, nil
	}
	if err != nil {
		return CA{}, false, err
	}
	if err := jsonsafe.Validate(payload); err != nil {
		return CA{}, false, domain.NewError(domain.ErrInvalidContract, "open active transparent CA", "active CA state is invalid or ambiguous")
	}
	var state caState
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.SchemaVersion != "v1" || !validCADirectoryPath(filepath.Join(s.root, state.Directory)) || filepath.Base(state.Directory) != state.Directory {
		return CA{}, false, domain.NewError(domain.ErrInvalidContract, "open active transparent CA", "active CA state is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CA{}, false, domain.NewError(domain.ErrInvalidContract, "open active transparent CA", "active CA state has trailing data")
	}
	ca, err := OpenCA(filepath.Join(s.root, state.Directory))
	if err != nil {
		return CA{}, false, err
	}
	return ca, true, nil
}

func (s *CAStore) validateCandidate(candidate CA) (CA, error) {
	if filepath.Dir(candidate.directory) != s.root {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "activate transparent CA", "CA is outside this store")
	}
	current, err := OpenCA(candidate.directory)
	if err != nil {
		return CA{}, err
	}
	for _, identity := range []struct {
		path     string
		expected os.FileInfo
	}{
		{current.directory, candidate.directoryInfo},
		{current.CertificatePath, candidate.certificateInfo},
		{current.KeyPath, candidate.keyInfo},
	} {
		matches, err := sameCAFile(identity.path, identity.expected)
		if err != nil || !matches {
			return CA{}, domain.NewError(domain.ErrInvalidContract, "activate transparent CA", "CA identity changed after staging")
		}
	}
	return current, nil
}

func readCAState(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 {
		return nil, domain.NewError(domain.ErrInvalidContract, "read active transparent CA", "active CA state permissions or type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, domain.NewError(domain.ErrInvalidContract, "read active transparent CA", "active CA state changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxCAStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxCAStateBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "read active transparent CA", "active CA state is too large")
	}
	return payload, nil
}

func writeCAStateAtomic(path string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".active-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
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
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncCADirectory(filepath.Dir(path))
}

func removeCAState(path, root string) error {
	if _, err := readCAState(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncCADirectory(root)
}
