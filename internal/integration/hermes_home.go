package integration

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
)

const maxHermesHomeEntries = 4096

// PrepareHermesHome creates a private, temporary HERMES_HOME containing the
// rewritten configuration. Existing Hermes state remains available through
// symlinks, while the user's config.yaml is never modified.
func PrepareHermesHome(sourceHome string, config []byte) (string, func() error, error) {
	if !filepath.IsAbs(sourceHome) || strings.ContainsRune(sourceHome, 0) {
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "source home must be an absolute safe path")
	}
	if len(config) == 0 || len(config) > maxHermesConfigBytes {
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "configuration is empty or too large")
	}
	info, err := os.Lstat(sourceHome)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "source home permissions or type are unsafe")
	}
	entries, err := readHermesHomeEntries(sourceHome, info, maxHermesHomeEntries+1)
	if err != nil {
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "source home could not be enumerated")
	}
	if len(entries) > maxHermesHomeEntries {
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "source home contains too many entries")
	}

	temporaryHome, err := os.MkdirTemp("", "agentveil-hermes-")
	if err != nil {
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "temporary home could not be created")
	}
	remove := func() error { return os.RemoveAll(temporaryHome) }
	fail := func() (string, func() error, error) {
		_ = remove()
		return "", nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "temporary home could not be populated")
	}
	for _, entry := range entries {
		if entry.Name() == "config.yaml" {
			continue
		}
		source := filepath.Join(sourceHome, entry.Name())
		destination := filepath.Join(temporaryHome, entry.Name())
		if err := os.Symlink(source, destination); err != nil {
			return fail()
		}
	}
	configPath := filepath.Join(temporaryHome, "config.yaml")
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail()
	}
	if _, err = file.Write(config); err != nil {
		_ = file.Close()
		return fail()
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return fail()
	}
	if err = file.Close(); err != nil {
		return fail()
	}
	current, err := os.Lstat(sourceHome)
	if err != nil || !os.SameFile(info, current) || !current.IsDir() || current.Mode().Perm()&0o022 != 0 {
		return fail()
	}

	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() { cleanupErr = remove() })
		return cleanupErr
	}
	return temporaryHome, cleanup, nil
}

func readHermesHomeEntries(path string, expected os.FileInfo, limit int) ([]os.DirEntry, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(expected, opened) || !opened.IsDir() || opened.Mode().Perm()&0o022 != 0 {
		directory.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "enumerate hermes home", "source home changed during validation")
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
