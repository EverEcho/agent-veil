package instance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const maxStateBytes = 4096

type State struct {
	SchemaVersion string    `json:"schema_version"`
	APIEndpoint   string    `json:"api_endpoint"`
	ProcessID     int       `json:"process_id"`
	StartedAt     time.Time `json:"started_at"`
}

func WriteState(path string, state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	if path == "" || !filepath.IsAbs(path) {
		return domain.NewError(domain.ErrInvalidContract, "write core state", "state path must be absolute")
	}
	if err := ensurePrivateDirectory(filepath.Dir(path), "write core state"); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".core-state-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
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
	return syncStateDirectory(filepath.Dir(path))
}

func LoadState(path string) (State, error) {
	if path == "" || !filepath.IsAbs(path) {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state path must be absolute")
	}
	if err := validatePrivateDirectory(filepath.Dir(path), "load core state"); err != nil {
		return State{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state file permissions or type are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return State{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state file changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return State{}, err
	}
	if len(payload) > maxStateBytes {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state file is too large")
	}
	if err := jsonsafe.Validate(payload); err != nil {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state file is invalid or ambiguous")
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state file is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return State{}, domain.NewError(domain.ErrInvalidContract, "load core state", "state file has trailing data")
	}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func RemoveState(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return domain.NewError(domain.ErrInvalidContract, "remove core state", "state path must be absolute")
	}
	if err := validatePrivateDirectory(filepath.Dir(path), "remove core state"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncStateDirectory(filepath.Dir(path))
}

func ensurePrivateDirectory(path, operation string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return domain.NewError(domain.ErrInvalidContract, operation, "private directory is unavailable")
	}
	return validatePrivateDirectory(path, operation)
}

func validatePrivateDirectory(path, operation string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, operation, "directory permissions or type are unsafe")
	}
	return nil
}

func syncStateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateState(state State) error {
	if state.SchemaVersion != "v1" || state.ProcessID <= 0 || state.StartedAt.IsZero() {
		return domain.NewError(domain.ErrInvalidContract, "validate core state", "state identity is invalid")
	}
	parsed, err := url.Parse(state.APIEndpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return domain.NewError(domain.ErrInvalidContract, "validate core state", "endpoint is invalid")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || portNumber == 0 {
		return domain.NewError(domain.ErrInvalidContract, "validate core state", "endpoint address is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return domain.NewError(domain.ErrInvalidContract, "validate core state", "endpoint must be loopback")
	}
	return nil
}
