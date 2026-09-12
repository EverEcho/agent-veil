package modelstore

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

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const MaxArtifactBytes int64 = 512 << 20

const maxManifestBytes = 16 << 10
const maxInstalledVersions = 256

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
}

func New(root string, verifyKey ed25519.PublicKey) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) || len(verifyKey) != ed25519.PublicKeySize {
		return nil, domain.NewError(domain.ErrInvalidContract, "create model store", "absolute root and Ed25519 verification key are required")
	}
	versions := filepath.Join(root, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return nil, err
	}
	for _, directory := range []string{root, versions} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return nil, domain.NewError(domain.ErrInvalidContract, "create model store", "model directory permissions or type are unsafe")
		}
	}
	return &Store{root: root, verifyKey: append(ed25519.PublicKey(nil), verifyKey...)}, nil
}

func (s *Store) Install(manifest Manifest, source io.Reader) error {
	if source == nil {
		return domain.NewError(domain.ErrInvalidContract, "install model", "model source is required")
	}
	if err := s.verifyManifest(manifest); err != nil {
		return err
	}
	versions := filepath.Join(s.root, "versions")
	finalDirectory := filepath.Join(versions, manifest.Version)
	if _, err := os.Lstat(finalDirectory); err == nil {
		return domain.NewError(domain.ErrInvalidContract, "install model", "model version is already installed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.MkdirTemp(versions, ".install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	artifactPath := filepath.Join(temporary, "model.onnx")
	artifact, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(artifact, hash), io.LimitReader(source, manifest.Size+1))
	if copyErr != nil {
		artifact.Close()
		return copyErr
	}
	if written != manifest.Size {
		artifact.Close()
		return domain.NewError(domain.ErrInvalidContract, "install model", "model size does not match manifest")
	}
	if hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		artifact.Close()
		return domain.NewError(domain.ErrInvalidContract, "install model", "model digest does not match manifest")
	}
	if err := artifact.Sync(); err != nil {
		artifact.Close()
		return err
	}
	if err := artifact.Close(); err != nil {
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

func (s *Store) Open(version string) (*os.File, Manifest, error) {
	if !versionPattern.MatchString(version) {
		return nil, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open model", "model version is invalid")
	}
	directory := filepath.Join(s.root, "versions", version)
	if err := validateVersionDirectory(directory, "model.onnx"); err != nil {
		return nil, Manifest{}, err
	}
	manifestPayload, err := readPrivateFile(filepath.Join(directory, "manifest.json"), maxManifestBytes)
	if err != nil {
		return nil, Manifest{}, err
	}
	if err := jsonsafe.Validate(manifestPayload); err != nil {
		return nil, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open model", "model manifest is invalid or ambiguous")
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Version != version {
		return nil, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open model", "model manifest does not match requested version")
	}
	if err := s.verifyManifest(manifest); err != nil {
		return nil, Manifest{}, err
	}
	artifact, err := openPrivateRegular(filepath.Join(directory, "model.onnx"))
	if err != nil {
		return nil, Manifest{}, err
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(artifact, manifest.Size+1))
	if err != nil || read != manifest.Size || hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		artifact.Close()
		return nil, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open model", "installed model failed integrity verification")
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		artifact.Close()
		return nil, Manifest{}, err
	}
	return artifact, manifest, nil
}

// List returns only versions whose signed manifest and artifact both verify.
func (s *Store) List() ([]Manifest, error) {
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
		return nil, domain.NewError(domain.ErrInvalidContract, "list models", "installed model versions exceed their limit")
	}
	result := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if !versionPattern.MatchString(entry.Name()) || !entry.IsDir() {
			return nil, domain.NewError(domain.ErrInvalidContract, "list models", "model versions directory contains an invalid entry")
		}
		file, manifest, err := s.Open(entry.Name())
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		result = append(result, manifest)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result, nil
}

func (s *Store) Activate(version string) error {
	file, _, err := s.Open(version)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	payload, err := json.Marshal(activeVersion{Version: version})
	if err != nil {
		return err
	}
	return writePrivateAtomic(filepath.Join(s.root, "active.json"), append(payload, '\n'))
}

func (s *Store) OpenActive() (*os.File, Manifest, error) {
	payload, err := readPrivateFile(filepath.Join(s.root, "active.json"), maxManifestBytes)
	if err != nil {
		return nil, Manifest{}, err
	}
	if err := jsonsafe.Validate(payload); err != nil {
		return nil, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open active model", "active model pointer is invalid or ambiguous")
	}
	var active activeVersion
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&active); err != nil {
		return nil, Manifest{}, domain.NewError(domain.ErrInvalidContract, "open active model", "active model pointer is invalid")
	}
	return s.Open(active.Version)
}

func (s *Store) verifyManifest(manifest Manifest) error {
	if manifest.SchemaVersion != "v1" || !versionPattern.MatchString(manifest.Version) || manifest.Size <= 0 || manifest.Size > MaxArtifactBytes {
		return domain.NewError(domain.ErrInvalidContract, "verify model manifest", "model identity or size is invalid")
	}
	digest, err := hex.DecodeString(manifest.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != manifest.SHA256 {
		return domain.NewError(domain.ErrInvalidContract, "verify model manifest", "model SHA-256 is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(s.verifyKey, signingPayload(manifest), signature) {
		return domain.NewError(domain.ErrInvalidContract, "verify model manifest", "model signature is invalid")
	}
	return nil
}

func signingPayload(manifest Manifest) []byte {
	return []byte(manifest.SchemaVersion + "\n" + manifest.Version + "\n" + strconv.FormatInt(manifest.Size, 10) + "\n" + manifest.SHA256 + "\n")
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := openPrivateRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, domain.NewError(domain.ErrInvalidContract, "read model metadata", "model metadata is too large")
	}
	return payload, nil
}

func openPrivateRegular(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "open model file", "model file permissions or type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "open model file", "model file changed during validation")
	}
	return file, nil
}

func validateVersionDirectory(path, artifactName string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "open model version", "model version directory permissions or type are unsafe")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 2 || entries[0].Name() != "manifest.json" || entries[1].Name() != artifactName {
		return domain.NewError(domain.ErrInvalidContract, "open model version", "model version directory contents are invalid")
	}
	return nil
}

func writePrivateAtomic(path string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".metadata-*.tmp")
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

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync model directory: %w", err)
	}
	return nil
}
