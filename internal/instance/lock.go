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
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock directory is unavailable")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock path cannot be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock path is unavailable")
	}
	file := flock.New(path)
	locked, err := file.TryLock()
	if err != nil {
		_ = file.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "operating-system lock failed")
	}
	if !locked {
		_ = file.Close()
		return nil, domain.NewError(domain.ErrCoreAlreadyRunning, "acquire core lock", "another AgentVeil Core holds the lock")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = file.Unlock()
		_ = file.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "acquire core lock", "lock permissions could not be restricted")
	}
	return &Lock{file: file}, nil
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
