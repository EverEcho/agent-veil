package desktopapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/instance"
)

const maxDesktopResponseBytes = 2 << 20

type Options struct {
	CoreExecutable  string
	ConfigDir       string
	ManagementToken string
	ReadyTimeout    time.Duration
	HTTPClient      *http.Client
}

type Status struct {
	Running    bool
	Owned      bool
	Endpoint   string
	InstanceID string
	Sessions   int
}

// Supervisor owns only Core processes that it started. An already-running Core
// is adopted for observation but is never terminated by the desktop process.
type Supervisor struct {
	mu      sync.Mutex
	options Options
	client  *http.Client
	process *os.Process
	status  Status
}

func NewSupervisor(options Options) (*Supervisor, error) {
	if !filepath.IsAbs(options.CoreExecutable) || !filepath.IsAbs(options.ConfigDir) || options.ReadyTimeout <= 0 || options.ReadyTimeout > time.Minute {
		return nil, errors.New("absolute Core executable/config directory and bounded ready timeout are required")
	}
	if options.ManagementToken == "" {
		secret := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, secret); err != nil {
			return nil, errors.New("generate desktop management token")
		}
		options.ManagementToken = base64.RawURLEncoding.EncodeToString(secret)
		for index := range secret {
			secret[index] = 0
		}
	}
	if len(options.ManagementToken) < 32 || len(options.ManagementToken) > 4096 {
		return nil, errors.New("desktop management token is invalid")
	}
	for _, character := range options.ManagementToken {
		if character < 0x21 || character > 0x7e {
			return nil, errors.New("desktop management token is invalid")
		}
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Supervisor{options: options, client: client}, nil
}

func (s *Supervisor) Token() string {
	if s == nil {
		return ""
	}
	return s.options.ManagementToken
}

func (s *Supervisor) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Ensure returns a healthy Core, starting one when no valid instance exists.
func (s *Supervisor) Ensure(ctx context.Context) (Status, error) {
	if s == nil || ctx == nil {
		return Status{}, errors.New("desktop supervisor and context are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if status, err := s.probeLocked(ctx); err == nil {
		status.Owned = s.process != nil
		s.status = status
		return status, nil
	}
	// A live Core with a different management token belongs to another
	// controller. Never race it by attempting a second Core startup.
	if state, err := instance.LoadState(filepath.Join(s.options.ConfigDir, "core.json")); err == nil && s.identityMatches(ctx, state) {
		return Status{}, errors.New("an existing Core is healthy but cannot be managed with this desktop token")
	}
	if s.process != nil {
		_ = s.process.Kill()
		s.process = nil
	}
	if err := ensurePrivateDirectory(s.options.ConfigDir); err != nil {
		return Status{}, err
	}
	logFile, err := openPrivateLog(filepath.Join(s.options.ConfigDir, "desktop-core.log"))
	if err != nil {
		return Status{}, err
	}
	command := exec.Command(s.options.CoreExecutable, "serve")
	command.Env = overlayEnvironment(os.Environ(), map[string]string{"VEIL_ADMIN_TOKEN": s.options.ManagementToken})
	command.Stdout, command.Stderr = logFile, logFile
	configureCoreCommand(command)
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return Status{}, err
	}
	_ = logFile.Close()
	s.process = command.Process
	go func() { _ = command.Wait() }()
	deadline := time.Now().Add(s.options.ReadyTimeout)
	for {
		status, probeErr := s.probeLocked(ctx)
		if probeErr == nil {
			status.Owned = true
			s.status = status
			return status, nil
		}
		if time.Now().After(deadline) {
			_ = s.process.Kill()
			s.process = nil
			s.status = Status{}
			return Status{}, fmt.Errorf("Core did not become ready: %w", probeErr)
		}
		select {
		case <-ctx.Done():
			_ = s.process.Kill()
			s.process = nil
			return Status{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("desktop configuration directory permissions are unsafe")
	}
	return nil
}

func openPrivateLog(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0o600)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("desktop Core log permissions or type are unsafe")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("desktop Core log changed while opening")
	}
	return file, nil
}

func (s *Supervisor) identityMatches(ctx context.Context, state instance.State) bool {
	var identity struct {
		APIVersion string `json:"api_version"`
		InstanceID string `json:"instance_id"`
	}
	return s.requestJSON(ctx, state.APIEndpoint+"/v1/identity", false, &identity) == nil && identity.APIVersion == core.APIVersion && identity.InstanceID == state.InstanceID
}

// Check refreshes health and the number of active Sessions.
func (s *Supervisor) Check(ctx context.Context) (Status, error) {
	if s == nil || ctx == nil {
		return Status{}, errors.New("desktop supervisor and context are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status, err := s.probeLocked(ctx)
	if err != nil {
		s.status.Running = false
		return s.status, err
	}
	status.Owned = s.process != nil
	s.status = status
	return status, nil
}

// StopIfIdle stops an owned Core only when it has no active Sessions. It
// returns false when Core must remain alive or belongs to another controller.
func (s *Supervisor) StopIfIdle(ctx context.Context) (bool, error) {
	if s == nil || ctx == nil {
		return false, errors.New("desktop supervisor and context are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status, err := s.probeLocked(ctx)
	if err != nil {
		if s.process == nil {
			return false, nil
		}
		_ = s.process.Kill()
		s.process = nil
		s.status = Status{}
		return true, nil
	}
	if s.process == nil || status.Sessions != 0 {
		s.status = status
		return false, nil
	}
	if err := stopCoreProcess(s.process); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return false, err
	}
	s.process = nil
	s.status = Status{}
	return true, nil
}

func (s *Supervisor) probeLocked(ctx context.Context) (Status, error) {
	state, err := instance.LoadState(filepath.Join(s.options.ConfigDir, "core.json"))
	if err != nil {
		return Status{}, err
	}
	if !s.identityMatches(ctx, state) {
		return Status{}, errors.New("Core identity is stale or incompatible")
	}
	var health map[string]string
	if err := s.requestJSON(ctx, state.APIEndpoint+"/v1/health", true, &health); err != nil || health["api_version"] != core.APIVersion || health["status"] == "" {
		return Status{}, errors.New("Core health is unavailable")
	}
	var sessions []json.RawMessage
	if err := s.requestJSON(ctx, state.APIEndpoint+"/v1/sessions", true, &sessions); err != nil {
		return Status{}, errors.New("Core Session inventory is unavailable")
	}
	return Status{Running: true, Endpoint: state.APIEndpoint, InstanceID: state.InstanceID, Sessions: len(sessions)}, nil
}

func (s *Supervisor) requestJSON(ctx context.Context, target string, authenticated bool, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set(core.APIVersionHeader, core.APIVersion)
	request.Header.Set("Accept-Encoding", "identity")
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+s.options.ManagementToken)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get(core.APIVersionHeader) != core.APIVersion {
		return fmt.Errorf("Core returned status %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxDesktopResponseBytes+1))
	if err != nil || len(payload) > maxDesktopResponseBytes {
		return errors.New("Core response exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("Core response contains trailing data")
	}
	return nil
}

func overlayEnvironment(base []string, overrides map[string]string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key := entry
		for index, character := range entry {
			if character == '=' {
				key = entry[:index]
				break
			}
		}
		if _, replaced := overrides[key]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}
