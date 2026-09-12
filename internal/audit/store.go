package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type Store struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	forbidden func() []string
}

func NewStore(path string, retention time.Duration, forbidden func() []string) (*Store, error) {
	if path == "" || retention <= 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create audit store", "path and positive retention are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return &Store{path: path, retention: retention, forbidden: forbidden}, nil
}

func (s *Store) Append(event domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var forbidden []string
	if s.forbidden != nil {
		forbidden = s.forbidden()
	}
	payload, err := Marshal(event, forbidden...)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (s *Store) Recent(now time.Time) ([]domain.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cutoff := now.Add(-s.retention)
	var events []domain.AuditEvent
	decoder := json.NewDecoder(bufio.NewReader(file))
	for {
		var event domain.AuditEvent
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "read audit", "audit file contains invalid data")
		}
		if !event.Timestamp.Before(cutoff) {
			events = append(events, event)
		}
	}
	return events, nil
}
