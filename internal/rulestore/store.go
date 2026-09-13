package rulestore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const (
	MaxArtifactBytes     int64 = 1 << 20
	maxManifestBytes     int64 = 16 << 10
	maxInstalledVersions       = 256
)

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	Version       string `json:"version"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	Signature     string `json:"signature"`
}

type activeVersion struct {
	Version string `json:"version"`
}

type Store struct {
	root      string
	verifyKey ed25519.PublicKey
	mu        sync.RWMutex
}

func New(root string, verifyKey ed25519.PublicKey) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) || len(verifyKey) != ed25519.PublicKeySize {
		return nil, domain.NewError(domain.ErrInvalidContract, "create rule store", "absolute root and Ed25519 verification key are required")
	}
	versions := filepath.Join(root, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return nil, err
	}
	for _, directory := range []string{root, versions} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return nil, domain.NewError(domain.ErrInvalidContract, "create rule store", "rule directory permissions or type are unsafe")
		}
	}
	return &Store{root: root, verifyKey: append(ed25519.PublicKey(nil), verifyKey...)}, nil
}

func (s *Store) Install(manifest Manifest, source io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == nil {
		return domain.NewError(domain.ErrInvalidContract, "install rule pack", "rule source is required")
	}
	if err := s.verifyManifest(manifest); err != nil {
		return err
	}
	versions := filepath.Join(s.root, "versions")
	finalDirectory := filepath.Join(versions, manifest.Version)
	if _, err := os.Lstat(finalDirectory); err == nil {
		return domain.NewError(domain.ErrInvalidContract, "install rule pack", "rule version is already installed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	count, err := installedEntryCount(versions, maxInstalledVersions+1)
	if err != nil {
		return err
	}
	if count >= maxInstalledVersions {
		return domain.NewError(domain.ErrInvalidContract, "install rule pack", "installed rule versions reached their limit")
	}
	temporary, err := os.MkdirTemp(versions, ".install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	payload, err := io.ReadAll(io.LimitReader(source, manifest.Size+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) != manifest.Size || digest(payload) != manifest.SHA256 {
		return domain.NewError(domain.ErrInvalidContract, "install rule pack", "rule size or digest does not match manifest")
	}
	if _, err := decodePack(payload); err != nil {
		return err
	}
	if err := writePrivateAtomic(filepath.Join(temporary, "rules.json"), payload); err != nil {
		return err
	}
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writePrivateAtomic(filepath.Join(temporary, "manifest.json"), append(manifestPayload, '\n')); err != nil {
		return err
	}
	if err := syncDirectory(temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, finalDirectory); err != nil {
		return err
	}
	return syncDirectory(versions)
}

func (s *Store) Open(version string) (detector.RulePack, Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.open(version)
}

func (s *Store) open(version string) (detector.RulePack, Manifest, error) {
	if !versionPattern.MatchString(version) {
		return detector.RulePack{}, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open rule pack", "rule version is invalid")
	}
	directory := filepath.Join(s.root, "versions", version)
	if err := validateRuleVersionDirectory(directory); err != nil {
		return detector.RulePack{}, Manifest{}, err
	}
	manifestPayload, err := readPrivateFile(filepath.Join(directory, "manifest.json"), maxManifestBytes)
	if err != nil {
		return detector.RulePack{}, Manifest{}, err
	}
	var manifest Manifest
	if err := decodeStrict(manifestPayload, &manifest); err != nil || manifest.Version != version {
		return detector.RulePack{}, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open rule pack", "rule manifest is invalid")
	}
	if err := s.verifyManifest(manifest); err != nil {
		return detector.RulePack{}, Manifest{}, err
	}
	payload, err := readPrivateFile(filepath.Join(directory, "rules.json"), manifest.Size)
	if err != nil {
		return detector.RulePack{}, Manifest{}, err
	}
	if int64(len(payload)) != manifest.Size || digest(payload) != manifest.SHA256 {
		return detector.RulePack{}, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open rule pack", "installed rule pack failed integrity verification")
	}
	pack, err := decodePack(payload)
	if err != nil {
		return detector.RulePack{}, Manifest{}, err
	}
	return pack, manifest, nil
}

// List returns only versions whose signed manifest and rule payload verify.
func (s *Store) List() ([]Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	directory, err := os.Open(filepath.Join(s.root, "versions"))
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maxInstalledVersions + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maxInstalledVersions {
		return nil, domain.NewError(domain.ErrInvalidContract, "list rule packs", "installed rule versions exceed their limit")
	}
	result := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if !versionPattern.MatchString(entry.Name()) || !entry.IsDir() {
			return nil, domain.NewError(domain.ErrInvalidContract, "list rule packs", "rule versions directory contains an invalid entry")
		}
		_, manifest, err := s.open(entry.Name())
		if err != nil {
			return nil, err
		}
		result = append(result, manifest)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result, nil
}

func (s *Store) Activate(version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.open(version); err != nil {
		return err
	}
	payload, err := json.Marshal(activeVersion{Version: version})
	if err != nil {
		return err
	}
	return writePrivateAtomic(filepath.Join(s.root, "active.json"), append(payload, '\n'))
}

// Deactivate removes only the active pointer so callers can immediately fall
// back to built-in rules without deleting any verified rollback versions.
func (s *Store) Deactivate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	activePath := filepath.Join(s.root, "active.json")
	info, err := os.Lstat(activePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return domain.NewError(domain.ErrInvalidContract, "deactivate rule pack", "active rule pointer is a directory")
	}
	if err := os.Remove(activePath); err != nil {
		return err
	}
	return syncDirectory(s.root)
}

// Remove deletes one verified inactive version. Active or malformed versions
// are retained so deletion cannot silently break the current data plane or
// conceal integrity failures.
func (s *Store) Remove(version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := s.open(version); err != nil {
		return err
	}
	activePath := filepath.Join(s.root, "active.json")
	payload, err := readPrivateFile(activePath, maxManifestBytes)
	if err == nil {
		var active activeVersion
		if decodeStrict(payload, &active) != nil {
			return domain.NewError(domain.ErrInvalidContract, "remove rule pack", "active rule pointer is invalid")
		}
		if active.Version == version {
			return domain.NewError(domain.ErrInvalidContract, "remove rule pack", "active rule version cannot be removed")
		}
		if _, _, err := s.open(active.Version); err != nil {
			return domain.NewError(domain.ErrInvalidContract, "remove rule pack", "active rule version is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Join(s.root, "versions", version)
	for _, name := range []string{"rules.json", "manifest.json"} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return syncDirectory(filepath.Join(s.root, "versions"))
}

func (s *Store) OpenActive() (detector.RulePack, Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload, err := readPrivateFile(filepath.Join(s.root, "active.json"), maxManifestBytes)
	if err != nil {
		return detector.RulePack{}, Manifest{}, err
	}
	var active activeVersion
	if err := decodeStrict(payload, &active); err != nil {
		return detector.RulePack{}, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open active rule pack", "active rule pointer is invalid")
	}
	return s.open(active.Version)
}

func installedEntryCount(path string, limit int) (int, error) {
	entries, err := readDirectoryEntries(path, limit)
	return len(entries), err
}

func readDirectoryEntries(path string, limit int) ([]os.DirEntry, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(limit)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (s *Store) verifyManifest(manifest Manifest) error {
	if manifest.SchemaVersion != "v1" || !versionPattern.MatchString(manifest.Version) || manifest.Size <= 0 || manifest.Size > MaxArtifactBytes {
		return domain.NewError(domain.ErrInvalidContract, "verify rule manifest", "rule identity or size is invalid")
	}
	digestBytes, err := hex.DecodeString(manifest.SHA256)
	if err != nil || len(digestBytes) != sha256.Size || hex.EncodeToString(digestBytes) != manifest.SHA256 {
		return domain.NewError(domain.ErrInvalidContract, "verify rule manifest", "rule SHA-256 is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != manifest.Signature || !ed25519.Verify(s.verifyKey, SigningPayload(manifest), signature) {
		return domain.NewError(domain.ErrInvalidContract, "verify rule manifest", "rule signature is invalid")
	}
	return nil
}

func SigningPayload(manifest Manifest) []byte {
	return []byte(manifest.SchemaVersion + "\n" + manifest.Version + "\n" + strconv.FormatInt(manifest.Size, 10) + "\n" + manifest.SHA256 + "\n")
}

func decodePack(payload []byte) (detector.RulePack, error) {
	var pack detector.RulePack
	if err := decodeStrict(payload, &pack); err != nil {
		return detector.RulePack{}, domain.NewError(domain.ErrInvalidContract, "load rule pack", "rule JSON is invalid or ambiguous")
	}
	if _, err := detector.NewDefaultWithRulePack(pack); err != nil {
		return detector.RulePack{}, err
	}
	return pack, nil
}

func decodeStrict(payload []byte, target any) error {
	if err := jsonsafe.Validate(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "open rule file", "rule file permissions or type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, domain.NewError(domain.ErrInvalidContract, "open rule file", "rule file changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, domain.NewError(domain.ErrInvalidContract, "read rule file", "rule file is too large")
	}
	return payload, nil
}

func writePrivateAtomic(path string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".rules-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(payload); err != nil {
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
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func validateRuleVersionDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "open rule version", "rule version directory permissions or type are unsafe")
	}
	entries, err := readDirectoryEntries(path, 3)
	if err != nil || len(entries) != 2 || entries[0].Name() != "manifest.json" || entries[1].Name() != "rules.json" {
		return domain.NewError(domain.ErrInvalidContract, "open rule version", "rule version directory contents are invalid")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync rule directory: %w", err)
	}
	return nil
}
