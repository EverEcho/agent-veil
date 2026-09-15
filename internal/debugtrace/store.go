// Package debugtrace owns the explicitly opt-in, local developer trace log.
// Unlike the security audit, traces may contain request bodies when the user
// enables that separate high-risk option.
package debugtrace

import (
	"bufio"
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
)

const (
	maxSettingsBytes     = 16 << 10
	maxTraceFileBytes    = 32 << 20
	MaxCapturedBodyBytes = 256 << 10
)

type Settings struct {
	SchemaVersion        string `json:"schema_version"`
	Enabled              bool   `json:"enabled"`
	CaptureRequestBodies bool   `json:"capture_request_bodies"`
}

func DefaultSettings() Settings { return Settings{SchemaVersion: "v1"} }

func (s Settings) Validate() error {
	if s.SchemaVersion != "v1" || s.CaptureRequestBodies && !s.Enabled {
		return domain.NewError(domain.ErrInvalidContract, "validate developer settings", "unsupported schema or request capture without developer mode")
	}
	return nil
}

type Finding struct {
	RuleID     string                 `json:"rule_id"`
	Category   string                 `json:"category"`
	Detector   string                 `json:"detector"`
	Severity   domain.Severity        `json:"severity"`
	Confidence float64                `json:"confidence"`
	Location   domain.ContentLocation `json:"location"`
	MatchBytes int                    `json:"match_bytes"`
	Action     domain.Action          `json:"action"`
}

type RequestTrace struct {
	Timestamp              time.Time        `json:"timestamp"`
	SessionID              string           `json:"session_id"`
	AgentID                string           `json:"agent_id"`
	SurfaceID              string           `json:"surface_id"`
	Protocol               domain.Protocol  `json:"protocol"`
	Method                 string           `json:"method"`
	Endpoint               string           `json:"endpoint"`
	ContentType            string           `json:"content_type,omitempty"`
	OriginalBodyBytes      int              `json:"original_body_bytes"`
	ProcessedBodyBytes     int              `json:"processed_body_bytes"`
	Findings               []Finding        `json:"findings"`
	Preview                string           `json:"preview,omitempty"`
	ErrorCode              domain.ErrorCode `json:"error_code,omitempty"`
	RequestBefore          string           `json:"request_before,omitempty"`
	RequestAfter           string           `json:"request_after,omitempty"`
	RequestBeforeTruncated bool             `json:"request_before_truncated,omitempty"`
	RequestAfterTruncated  bool             `json:"request_after_truncated,omitempty"`
}

type Store struct {
	mu           sync.Mutex
	settingsPath string
	tracePath    string
	retention    time.Duration
	settings     Settings
	maxBytes     int64
}

func NewStore(settingsPath, tracePath string, retention time.Duration) (*Store, error) {
	if settingsPath == "" || tracePath == "" || !filepath.IsAbs(settingsPath) || !filepath.IsAbs(tracePath) || filepath.Dir(settingsPath) != filepath.Dir(tracePath) || retention <= 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create developer trace store", "absolute colocated paths and positive retention are required")
	}
	directory := filepath.Dir(settingsPath)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create developer trace store", "trace directory permissions or type are unsafe")
	}
	store := &Store{settingsPath: settingsPath, tracePath: tracePath, retention: retention, settings: DefaultSettings(), maxBytes: maxTraceFileBytes}
	settings, err := store.loadSettingsLocked()
	if err == nil {
		store.settings = settings
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := store.Prune(time.Now().UTC()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

func (s *Store) SaveSettings(settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicWrite(s.settingsPath, ".developer-settings-*.tmp", payload); err != nil {
		return err
	}
	s.settings = settings
	return nil
}

func (s *Store) Append(trace RequestTrace) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.settings.Enabled {
		return nil
	}
	if !s.settings.CaptureRequestBodies {
		trace.RequestBefore = ""
		trace.RequestAfter = ""
		trace.RequestBeforeTruncated = false
		trace.RequestAfterTruncated = false
	}
	payload, err := json.Marshal(trace)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if int64(len(payload)) > s.maxBytes {
		return domain.NewError(domain.ErrInvalidContract, "append developer trace", "trace exceeds file capacity")
	}
	if err := s.compactLocked(int64(len(payload))); err != nil {
		return err
	}
	file, err := openPrivateAppend(s.tracePath)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	return file.Sync()
}

func (s *Store) Recent(now time.Time, limit int) ([]RequestTrace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	traces, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-s.retention)
	result := traces[:0]
	for _, trace := range traces {
		if !trace.Timestamp.Before(cutoff) {
			result = append(result, trace)
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result, nil
}

func (s *Store) Prune(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	traces, err := s.readLocked()
	if err != nil {
		return err
	}
	cutoff := now.Add(-s.retention)
	retained := traces[:0]
	for _, trace := range traces {
		if !trace.Timestamp.Before(cutoff) {
			retained = append(retained, trace)
		}
	}
	if len(retained) == len(traces) {
		return nil
	}
	return s.replaceLocked(retained)
}

func CaptureBody(body []byte) (string, bool) {
	if len(body) <= MaxCapturedBodyBytes {
		return string(body), false
	}
	return string(body[:MaxCapturedBodyBytes]), true
}

func (s *Store) loadSettingsLocked() (Settings, error) {
	payload, err := readPrivateFile(s.settingsPath, maxSettingsBytes)
	if err != nil {
		return Settings{}, err
	}
	if err := jsonsafe.Validate(payload); err != nil {
		return Settings{}, domain.NewError(domain.ErrInvalidContract, "load developer settings", "settings JSON is invalid or ambiguous")
	}
	var settings Settings
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return Settings{}, err
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func (s *Store) readLocked() ([]RequestTrace, error) {
	payload, err := readPrivateFile(s.tracePath, int(s.maxBytes))
	if errors.Is(err, os.ErrNotExist) {
		return []RequestTrace{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]RequestTrace, 0)
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 64<<10), int(s.maxBytes))
	for scanner.Scan() {
		line := scanner.Bytes()
		if err := jsonsafe.Validate(line); err != nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "read developer traces", "trace log contains invalid JSON")
		}
		var trace RequestTrace
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&trace); err != nil {
			return nil, err
		}
		result = append(result, trace)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) compactLocked(incoming int64) error {
	info, err := os.Lstat(s.tracePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validatePrivateFile(info); err != nil {
		return err
	}
	if info.Size()+incoming <= s.maxBytes {
		return nil
	}
	traces, err := s.readLocked()
	if err != nil {
		return err
	}
	remaining := s.maxBytes - incoming
	start := len(traces)
	for start > 0 {
		payload, err := json.Marshal(traces[start-1])
		if err != nil || int64(len(payload)+1) > remaining {
			break
		}
		remaining -= int64(len(payload) + 1)
		start--
	}
	return s.replaceLocked(traces[start:])
}

func (s *Store) replaceLocked(traces []RequestTrace) error {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, trace := range traces {
		if err := encoder.Encode(trace); err != nil {
			return err
		}
	}
	return atomicWrite(s.tracePath, ".developer-traces-*.tmp", payload.Bytes())
}

func readPrivateFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFile(info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, domain.NewError(domain.ErrInvalidContract, "read private file", "file changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > limit {
		return nil, domain.NewError(domain.ErrInvalidContract, "read private file", "file exceeds its size limit")
	}
	return payload, nil
}

func openPrivateAppend(path string) (*os.File, error) {
	for attempt := 0; attempt < 2; attempt++ {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
			if errors.Is(createErr, os.ErrExist) {
				continue
			}
			return file, createErr
		}
		if err != nil || validatePrivateFile(info) != nil {
			return nil, domain.NewError(domain.ErrInvalidContract, "open developer trace", "trace file permissions or type are unsafe")
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			file.Close()
			return nil, domain.NewError(domain.ErrInvalidContract, "open developer trace", "trace file changed during validation")
		}
		return file, nil
	}
	return nil, domain.NewError(domain.ErrInvalidContract, "open developer trace", "trace file changed during open")
}

func validatePrivateFile(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "validate private file", "file permissions or type are unsafe")
	}
	return nil
}

func atomicWrite(path, pattern string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), pattern)
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
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
