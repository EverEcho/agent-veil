package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const MaxManagedManifestBytes = 1 << 20

// FileSnapshotSource turns one managed AgentManifest file into revisioned
// snapshots for Monitor. It rejects links, writable-by-others files, ambiguous
// JSON, and identity changes so a transient replacement cannot preserve a stale
// Protected claim.
type FileSnapshotSource struct {
	path string
}

func NewFileSnapshotSource(path string) (*FileSnapshotSource, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, domain.NewError(domain.ErrInvalidContract, "create managed file snapshot", "manifest path must be absolute and safe")
	}
	return &FileSnapshotSource{path: filepath.Clean(path)}, nil
}

func (s *FileSnapshotSource) Snapshot(ctx context.Context) (string, domain.AgentManifest, error) {
	if s == nil || ctx == nil {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "source and context are required")
	}
	select {
	case <-ctx.Done():
		return "", domain.AgentManifest{}, ctx.Err()
	default:
	}
	before, err := os.Lstat(s.path)
	if err != nil {
		return "", domain.AgentManifest{}, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 || before.Size() <= 0 || before.Size() > MaxManagedManifestBytes {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest type, permissions, or size are unsafe")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return "", domain.AgentManifest{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest changed before it was read")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxManagedManifestBytes+1))
	if err != nil || len(content) == 0 || len(content) > MaxManagedManifestBytes {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest could not be read within its limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(content)) || !after.ModTime().Equal(opened.ModTime()) {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest changed while it was read")
	}
	select {
	case <-ctx.Done():
		return "", domain.AgentManifest{}, ctx.Err()
	default:
	}
	if err := jsonsafe.Validate(content); err != nil {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest JSON is invalid or ambiguous")
	}
	var manifest domain.AgentManifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest schema is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", domain.AgentManifest{}, domain.NewError(domain.ErrInvalidContract, "read managed file snapshot", "manifest contains trailing data")
	}
	if err := manifest.Validate(); err != nil {
		return "", domain.AgentManifest{}, err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), manifest, nil
}
