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
	store := &Store{path: path, retention: retention, forbidden: forbidden}
	if err := store.Prune(time.Now().UTC()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Append(event domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.Timestamp.Before(time.Now().UTC().Add(-s.retention)) {
		return nil
	}
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
	events, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-s.retention)
	result := events[:0]
	for _, event := range events {
		if !event.Timestamp.Before(cutoff) {
			result = append(result, event)
		}
	}
	return result, nil
}

func (s *Store) Prune(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	events, err := s.readLocked()
	if err != nil {
		return err
	}
	cutoff := now.Add(-s.retention)
	retained := events[:0]
	for _, event := range events {
		if !event.Timestamp.Before(cutoff) {
			retained = append(retained, event)
		}
	}
	if len(retained) == len(events) {
		return nil
	}
	return s.replaceLocked(retained)
}

func (s *Store) readLocked() ([]domain.AuditEvent, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []domain.AuditEvent
	decoder := json.NewDecoder(bufio.NewReader(file))
	for {
		var event domain.AuditEvent
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "read audit", "audit file contains invalid data")
		}
		events = append(events, event)
	}
	return events, nil
}

func (s *Store) replaceLocked(events []domain.AuditEvent) error {
	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".audit-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			temporary.Close()
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, s.path)
}
