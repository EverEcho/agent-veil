package instance

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/gofrs/flock"
)

type Lock struct {
	file *flock.Flock
}

func Acquire(path string) (*Lock, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock path must be absolute")
	}
	directory := filepath.Dir(path)
	if err := ensurePrivateDirectory(directory, "acquire core lock"); err != nil {
		return nil, err
	}
	if err := createLockFile(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock path is unavailable")
	}
	if err := validateLockFile(before); err != nil {
		return nil, err
	}
	file := flock.New(path, flock.SetPermissions(0o600))
	locked, err := file.TryLock()
	if err != nil {
		_ = file.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "operating-system lock failed")
	}
	if !locked {
		_ = file.Close()
		return nil, domain.NewError(domain.ErrCoreAlreadyRunning, "acquire core lock", "another AgentVeil Core holds the lock")
	}
	after, err := os.Lstat(path)
	if err != nil || validateLockFile(after) != nil || !os.SameFile(before, after) {
		_ = file.Unlock()
		_ = file.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock file changed during acquisition")
	}
	return &Lock{file: file}, nil
}

func createLockFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock file could not be created")
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncStateDirectory(filepath.Dir(path))
}

func validateLockFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock file permissions or type are unsafe")
	}
	return nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	if err := l.file.Unlock(); err != nil {
		return err
	}
	return l.file.Close()
}
