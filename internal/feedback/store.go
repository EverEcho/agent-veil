package feedback

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
	"github.com/agentveil/agentveil/internal/policy"
)

const (
	maxFeedbackBytes   = 4 << 20
	maxFeedbackEntries = 2048
)

type Entry struct {
	Timestamp       time.Time       `json:"timestamp"`
	RuleID          string          `json:"rule_id"`
	Category        string          `json:"category"`
	Detector        string          `json:"detector"`
	Severity        domain.Severity `json:"severity"`
	Confidence      float64         `json:"confidence"`
	SuggestedAction domain.Action   `json:"suggested_action"`
	PolicyAction    domain.Action   `json:"policy_action"`
	Scope           policy.Scope    `json:"scope"`
}

type document struct {
	SchemaVersion string  `json:"schema_version"`
	Entries       []Entry `json:"entries"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, domain.NewError(domain.ErrInvalidContract, "create feedback store", "path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create feedback store", "feedback directory permissions or type are unsafe")
	}
	return &Store{path: path}, nil
}

func (s *Store) Append(entry Entry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	document, err := s.loadLocked()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		document = documentWithEntries(nil)
	}
	document.Entries = append(document.Entries, entry)
	if len(document.Entries) > maxFeedbackEntries {
		document.Entries = append([]Entry(nil), document.Entries[len(document.Entries)-maxFeedbackEntries:]...)
	}
	return s.saveLocked(document)
}

func (s *Store) Recent() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	document, err := s.loadLocked()
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	return append([]Entry(nil), document.Entries...), nil
}

func (e Entry) Validate() error {
	finding := domain.Finding{RuleID: e.RuleID, Category: e.Category, Detector: e.Detector, Severity: e.Severity, Confidence: e.Confidence, SuggestedAction: e.SuggestedAction, Location: domain.ContentLocation{Path: "/metadata", Start: 0, End: 1}}
	if e.Timestamp.IsZero() || finding.Validate(1) != nil || !e.PolicyAction.Valid() || e.Scope.Validate() != nil || e.Scope.FindingType != e.Category {
		return domain.NewError(domain.ErrInvalidContract, "validate feedback", "feedback metadata is invalid")
	}
	return nil
}

func documentWithEntries(entries []Entry) document {
	if entries == nil {
		entries = []Entry{}
	}
	return document{SchemaVersion: "v1", Entries: entries}
}

func (s *Store) loadLocked() (document, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return document{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxFeedbackBytes {
		return document{}, domain.NewError(domain.ErrInvalidContract, "load feedback", "feedback file permissions, type, or size are unsafe")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return document{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return document{}, domain.NewError(domain.ErrInvalidContract, "load feedback", "feedback file changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxFeedbackBytes+1))
	if err != nil || len(payload) > maxFeedbackBytes || jsonsafe.Validate(payload) != nil {
		return document{}, domain.NewError(domain.ErrInvalidContract, "load feedback", "feedback JSON is invalid or oversized")
	}
	var result document
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return document{}, domain.NewError(domain.ErrInvalidContract, "load feedback", "feedback JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || result.SchemaVersion != "v1" || len(result.Entries) > maxFeedbackEntries {
		return document{}, domain.NewError(domain.ErrInvalidContract, "load feedback", "feedback document is invalid")
	}
	for _, entry := range result.Entries {
		if err := entry.Validate(); err != nil {
			return document{}, err
		}
	}
	return result, nil
}

func (s *Store) saveLocked(document document) error {
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > maxFeedbackBytes {
		return domain.NewError(domain.ErrInvalidContract, "save feedback", "feedback file exceeds its size limit")
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".feedback-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
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
	if err := os.Rename(temporary, s.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
