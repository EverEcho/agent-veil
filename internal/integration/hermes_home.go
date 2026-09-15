package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/jsonsafe"
)

const maxHermesHomeEntries = 4096
const hermesLaunchRootMarker = ".agentveil-owned-launch-root"
const hermesLaunchRootMarkerContent = "agentveil-hermes-launches-v1\n"

// PrepareHermesHome creates a private, temporary HERMES_HOME containing the
// rewritten configuration. Existing Hermes state remains available through
// symlinks, while the user's config.yaml is never modified.
func PrepareHermesHome(sourceHome string, config []byte) (string, func() error, error) {
	return prepareHermesHome(sourceHome, "", config, nil)
}

func prepareHermesHome(sourceHome, temporaryRoot string, config []byte, protectedEnvironment map[string]string) (string, func() error, error) {
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

	if temporaryRoot != "" {
		if err := ensureHermesLaunchRoot(temporaryRoot); err != nil {
			return "", nil, err
		}
	}
	temporaryHome, err := os.MkdirTemp(temporaryRoot, "agentveil-hermes-")
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
		if entry.Name() == ".env" && len(protectedEnvironment) != 0 {
			content, readErr := readHermesEnvironment(source)
			if readErr != nil || writeHermesEnvironment(destination, content, protectedEnvironment) != nil {
				return fail()
			}
			continue
		}
		if entry.Name() == "auth.json" && protectedEnvironment["HERMES_CODEX_BASE_URL"] != "" {
			content, readErr := readHermesPrivateFile(source)
			if readErr != nil {
				return fail()
			}
			rewritten, rewriteErr := rewriteHermesCodexAuth(content, protectedEnvironment["HERMES_CODEX_BASE_URL"])
			if rewriteErr != nil || writeHermesPrivateFile(destination, rewritten) != nil {
				return fail()
			}
			continue
		}
		if err := os.Symlink(source, destination); err != nil {
			return fail()
		}
	}
	if len(protectedEnvironment) != 0 {
		environmentPath := filepath.Join(temporaryHome, ".env")
		if _, err := os.Lstat(environmentPath); errors.Is(err, os.ErrNotExist) {
			if writeHermesEnvironment(environmentPath, nil, protectedEnvironment) != nil {
				return fail()
			}
		} else if err != nil {
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

// ResetHermesLaunchRoot removes only AgentVeil-owned launch directories after
// a new Core has claimed the exclusive instance lock. The ownership marker
// prevents an accidentally configured path from becoming a deletion target.
func ResetHermesLaunchRoot(root string) error {
	if err := ensureHermesLaunchRoot(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > maxHermesHomeEntries+1 {
		return domain.NewError(domain.ErrInvalidContract, "reset Hermes launch root", "launch root could not be enumerated within its bound")
	}
	for _, entry := range entries {
		if entry.Name() == hermesLaunchRootMarker {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "agentveil-hermes-") {
			// A marked root can contain data left by an older AgentVeil layout or
			// by a user. Unknown entries are outside this cleanup contract: keep
			// them and continue recovering known, owned Hermes sessions.
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return domain.NewError(domain.ErrInvalidContract, "reset Hermes launch root", "stale launch directory could not be removed")
		}
	}
	if err := syncHermesDirectory(root); err != nil {
		return domain.NewError(domain.ErrInvalidContract, "reset Hermes launch root", "launch root cleanup could not be persisted")
	}
	return nil
}

func ensureHermesLaunchRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || strings.ContainsRune(root, 0) {
		return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "launch root must be an absolute safe path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "launch root is unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "launch root permissions or type are unsafe")
	}
	marker := filepath.Join(root, hermesLaunchRootMarker)
	markerInfo, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		entries, readErr := os.ReadDir(root)
		if readErr != nil || len(entries) != 0 {
			return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "unmarked launch root is not empty")
		}
		file, createErr := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "ownership marker could not be created")
		}
		_, writeErr := file.WriteString(hermesLaunchRootMarkerContent)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || syncHermesDirectory(root) != nil {
			return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "ownership marker could not be persisted")
		}
		markerInfo, err = os.Lstat(marker)
	}
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm()&0o077 != 0 || markerInfo.Size() != int64(len(hermesLaunchRootMarkerContent)) {
		return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "ownership marker is unsafe")
	}
	content, readErr := os.ReadFile(marker)
	if readErr != nil || string(content) != hermesLaunchRootMarkerContent {
		return domain.NewError(domain.ErrInvalidContract, "prepare Hermes launch root", "ownership marker is invalid")
	}
	return nil
}

func syncHermesDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readHermesEnvironment(path string) ([]byte, error) {
	return readHermesPrivateFile(path)
}

func readHermesPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxHermesConfigBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "environment file type or size is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "environment file changed before it was copied")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxHermesConfigBytes+1))
	if err != nil || len(content) > maxHermesConfigBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "environment file could not be read safely")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(content)) || !after.ModTime().Equal(opened.ModTime()) {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "environment file changed while it was copied")
	}
	return content, nil
}

func rewriteHermesCodexAuth(content []byte, baseURL string) ([]byte, error) {
	if jsonsafe.Validate(content) != nil || strings.ContainsAny(baseURL, "\x00\r\n") {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex authentication state is invalid")
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil || root == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex authentication state is invalid")
	}
	credentialPool, ok := root["credential_pool"].(map[string]any)
	if !ok {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex credential pool is missing")
	}
	rawEntries, exists := credentialPool["openai-codex"]
	entries, valid := rawEntries.([]any)
	if !exists || !valid || len(entries) == 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex credential pool is missing or invalid")
	}
	for _, rawEntry := range entries {
		entry, valid := rawEntry.(map[string]any)
		if !valid || strings.TrimSpace(stringValue(entry["access_token"])) == "" {
			return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex credential pool entry is invalid")
		}
		entry["base_url"] = baseURL
		if _, exists := entry["runtime_base_url"]; exists {
			entry["runtime_base_url"] = baseURL
		}
		// Hermes 0.20.x re-seeds device_code entries from providers.openai-codex
		// with a hard-coded upstream URL whenever the pool is loaded. The protected
		// copy suppresses that seed and retains the copied entry as a manual source.
		// This changes only the isolated HERMES_HOME used for this launch.
		if stringValue(entry["source"]) == "device_code" {
			entry["source"] = "manual:device_code"
		}
	}
	suppressed, ok := root["suppressed_sources"].(map[string]any)
	if !ok {
		suppressed = make(map[string]any)
		root["suppressed_sources"] = suppressed
	}
	current := make([]any, 0, 1)
	if raw, exists := suppressed["openai-codex"]; exists {
		values, valid := raw.([]any)
		if !valid {
			return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex suppression state is invalid")
		}
		current = append(current, values...)
	}
	found := false
	for _, value := range current {
		if stringValue(value) == "device_code" {
			found = true
			break
		}
	}
	if !found {
		current = append(current, "device_code")
	}
	suppressed["openai-codex"] = current
	rewritten, err := json.Marshal(root)
	if err != nil || len(rewritten) == 0 || len(rewritten) > maxHermesConfigBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "Codex authentication state could not be rewritten")
	}
	return append(rewritten, '\n'), nil
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func writeHermesPrivateFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func writeHermesEnvironment(path string, source []byte, overrides map[string]string) error {
	allowed := map[string]struct{}{
		"HERMES_CODEX_BASE_URL":     {},
		"HERMES_IGNORE_USER_CONFIG": {},
		"HERMES_INFERENCE_PROVIDER": {},
		"HERMES_TUI_PROVIDER":       {},
	}
	keys := make([]string, 0, len(overrides))
	for key, value := range overrides {
		if _, ok := allowed[key]; !ok || strings.ContainsAny(value, "\x00\r\n") {
			return domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "protected environment override is invalid")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var content bytes.Buffer
	content.Write(source)
	if content.Len() != 0 && content.Bytes()[content.Len()-1] != '\n' {
		content.WriteByte('\n')
	}
	content.WriteString("# AgentVeil protected launch overrides; last assignment wins.\n")
	for _, key := range keys {
		content.WriteString(key)
		content.WriteByte('=')
		content.WriteString(overrides[key])
		content.WriteByte('\n')
	}
	if content.Len() > maxHermesConfigBytes {
		return domain.NewError(domain.ErrInvalidContract, "prepare hermes home", "protected environment exceeds its size limit")
	}
	return writeHermesPrivateFile(path, content.Bytes())
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
