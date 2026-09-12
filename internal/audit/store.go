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
	maxBytes  int64
}

const maxAuditFileBytes int64 = 64 << 20

func NewStore(path string, retention time.Duration, forbidden func() []string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || retention <= 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create audit store", "absolute path and positive retention are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	store := &Store{path: path, retention: retention, forbidden: forbidden, maxBytes: maxAuditFileBytes}
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
	record := append(payload, '\n')
	if int64(len(record)) > s.maxBytes {
		return domain.NewError(domain.ErrInvalidContract, "append audit", "audit event is too large")
	}
	if err := s.compactForAppendLocked(int64(len(record))); err != nil {
		return err
	}
	file, err := openAuditAppend(s.path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(record); err != nil {
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
	file, err := openAuditRead(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > s.maxBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "read audit", "audit file is too large")
	}
	var events []domain.AuditEvent
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(file, s.maxBytes+1)))
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
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return err
	}
	return syncAuditDirectory(directory)
}

func (s *Store) compactForAppendLocked(recordBytes int64) error {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateAuditFileInfo(info); err != nil {
		return err
	}
	if info.Size()+recordBytes <= s.maxBytes {
		return nil
	}
	events, err := s.readLocked()
	if err != nil {
		return err
	}
	remaining := s.maxBytes - recordBytes
	start := len(events)
	for start > 0 {
		payload, err := json.Marshal(events[start-1])
		if err != nil {
			return err
		}
		size := int64(len(payload) + 1)
		if size > remaining {
			break
		}
		remaining -= size
		start--
	}
	return s.replaceLocked(events[start:])
}

func openAuditRead(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validateAuditFileInfo(info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !os.SameFile(info, opened) {
		file.Close()
		return nil, domain.NewError(domain.ErrInvalidContract, "open audit", "audit file changed during validation")
	}
	return file, nil
}

func openAuditAppend(path string) (*os.File, error) {
	for attempt := 0; attempt < 2; attempt++ {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
			if errors.Is(createErr, os.ErrExist) {
				continue
			}
			return file, createErr
		}
		if err != nil {
			return nil, err
		}
		if err := validateAuditFileInfo(info); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		opened, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, err
		}
		if !os.SameFile(info, opened) {
			file.Close()
			continue
		}
		return file, nil
	}
	return nil, domain.NewError(domain.ErrInvalidContract, "open audit", "audit file changed during validation")
}

func validateAuditFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "open audit", "audit file permissions or type are unsafe")
	}
	return nil
}

func syncAuditDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
