package integration

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const codexDesktopMarker = ".agentveil-codex-desktop-launch"
const codexDesktopRootMarker = ".agentveil-owned-codex-desktop-root"
const codexDesktopRootMarkerContent = "agentveil-codex-desktop-root-v1\n"
const maxCodexDesktopAuthBytes = 8 << 20
const maxCodexDesktopHomeEntries = 4096

// PrepareCodexDesktopLaunch creates an isolated Codex home for the official
// desktop application. The user's Codex configuration is never modified.
func PrepareCodexDesktopLaunch(agent domain.AgentInstance, desktopExecutable, sourceHome, temporaryRoot, baseURL string, hasAPIKey bool, args []string, coreEndpoint, sessionID, routeToken string) (LaunchPlan, error) {
	if agent.Kind != "codex-desktop" {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "agent kind is not Codex Desktop")
	}
	plan, err := PrepareLaunch(agent, args, coreEndpoint, sessionID, "", routeToken)
	if err != nil {
		return LaunchPlan{}, err
	}
	if !filepath.IsAbs(desktopExecutable) || strings.ContainsRune(desktopExecutable, 0) || !filepath.IsAbs(sourceHome) || !filepath.IsAbs(temporaryRoot) {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "desktop executable and launch directories must be absolute")
	}
	info, err := os.Lstat(desktopExecutable)
	if err != nil || !info.Mode().IsRegular() {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "official desktop executable was not found")
	}
	if err := ensureCodexDesktopRoot(temporaryRoot); err != nil {
		return LaunchPlan{}, err
	}
	temporaryHome, err := os.MkdirTemp(temporaryRoot, "session-")
	if err != nil {
		return LaunchPlan{}, err
	}
	cleanup := func() error { return cleanupCodexDesktopHome(temporaryHome) }
	fail := func(cause error) (LaunchPlan, error) {
		return LaunchPlan{}, errors.Join(cause, cleanup())
	}
	if err := linkCodexDesktopState(sourceHome, temporaryHome); err != nil {
		return fail(err)
	}
	if err := writePrivateFile(filepath.Join(temporaryHome, codexDesktopMarker), []byte("agentveil-codex-desktop-v1\n")); err != nil {
		return fail(err)
	}
	config := renderCodexDesktopConfig(baseURL, hasAPIKey)
	if err := writePrivateFile(filepath.Join(temporaryHome, "config.toml"), []byte(config)); err != nil {
		return fail(err)
	}
	auth, found, err := readCodexDesktopAuth(filepath.Join(sourceHome, "auth.json"))
	if err != nil {
		return fail(err)
	}
	if found {
		defer clearSensitiveBytes(auth)
		if err := writePrivateFile(filepath.Join(temporaryHome, "auth.json"), auth); err != nil {
			return fail(err)
		}
	}
	plan.Executable = desktopExecutable
	plan.Environment["CODEX_HOME"] = temporaryHome
	plan.cleanup = cleanup
	return plan, nil
}

// linkCodexDesktopState exposes the user's existing conversations and normal
// desktop state inside the isolated launch home without sharing configuration
// or credentials. Directories use symlinks so newly created conversation files
// persist in the original Codex state; regular files use hard links when the
// filesystem permits it so SQLite state remains shared without being copied.
func linkCodexDesktopState(sourceHome, temporaryHome string) error {
	sourceInfo, err := os.Lstat(sourceHome)
	if err != nil || !sourceInfo.IsDir() || runtime.GOOS != "windows" && sourceInfo.Mode().Perm()&0o022 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex data directory is unsafe")
	}
	entries, err := readHermesHomeEntries(sourceHome, sourceInfo, maxCodexDesktopHomeEntries+1)
	if err != nil || len(entries) > maxCodexDesktopHomeEntries {
		return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex data directory could not be enumerated safely")
	}
	for _, entry := range entries {
		name := entry.Name()
		if codexDesktopPrivateOrRuntimeEntry(name) {
			continue
		}
		source := filepath.Join(sourceHome, name)
		destination := filepath.Join(temporaryHome, name)
		info, infoErr := os.Lstat(source)
		if infoErr != nil {
			return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex state changed while it was linked")
		}
		switch {
		case info.IsDir() || info.Mode()&os.ModeSymlink != 0:
			err = os.Symlink(source, destination)
		case info.Mode().IsRegular():
			err = os.Link(source, destination)
			if err != nil {
				err = os.Symlink(source, destination)
			}
		default:
			return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex state contains an unsupported file type")
		}
		if err != nil {
			return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex state could not be linked")
		}
	}
	current, err := os.Lstat(sourceHome)
	if err != nil || !os.SameFile(sourceInfo, current) {
		return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex data directory changed during launch")
	}
	return nil
}

func codexDesktopPrivateOrRuntimeEntry(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "config.toml") || strings.HasPrefix(lower, "auth.json") || strings.Contains(lower, "codex_auth") || strings.Contains(lower, "oauth-lock") || strings.HasPrefix(lower, "..codex-global-state.json.tmp-") {
		return true
	}
	switch lower {
	case "ipc", "process_manager", "thread-writer-locks", ".tmp", "tmp", "node_repl", "shell_snapshots", codexDesktopMarker:
		return true
	default:
		return false
	}
}

func renderCodexDesktopConfig(baseURL string, hasAPIKey bool) string {
	auth := "requires_openai_auth = true"
	if hasAPIKey {
		auth = `env_key = "OPENAI_API_KEY"`
	}
	return fmt.Sprintf(`model_provider = "agentveil"
features.enable_request_compression = false
features.apps = false

[model_providers.agentveil]
name = "AgentVeil protected Codex Desktop"
base_url = %q
wire_api = "responses"
%s
supports_websockets = false
env_http_headers = { "X-Veil-Session" = "VEIL_SESSION_ID", "X-Veil-Route-Token" = "VEIL_PROTECTION_TOKEN" }
`, baseURL, auth)
}

func readCodexDesktopAuth(path string) ([]byte, bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !before.Mode().IsRegular() || runtime.GOOS != "windows" && before.Mode().Perm()&0o022 != 0 || before.Size() < 1 || before.Size() > maxCodexDesktopAuthBytes {
		return nil, false, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex login file must be a regular file that other accounts cannot modify")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, false, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex authentication state changed during validation")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxCodexDesktopAuthBytes+1))
	if err != nil || len(payload) < 1 || len(payload) > maxCodexDesktopAuthBytes {
		return nil, false, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex authentication state could not be read safely")
	}
	return payload, true, nil
}

func writePrivateFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func cleanupCodexDesktopHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Base(home) == "." {
		return domain.NewError(domain.ErrInvalidContract, "clean Codex Desktop launch", "temporary home is invalid")
	}
	marker := filepath.Join(home, codexDesktopMarker)
	payload, err := os.ReadFile(marker)
	if err != nil || string(payload) != "agentveil-codex-desktop-v1\n" {
		return domain.NewError(domain.ErrInvalidContract, "clean Codex Desktop launch", "temporary home ownership could not be verified")
	}
	if err := validateCodexDesktopRoot(filepath.Dir(home)); err != nil {
		return err
	}
	return os.RemoveAll(home)
}

func ensureCodexDesktopRoot(root string) error {
	if !filepath.IsAbs(root) || strings.ContainsRune(root, 0) {
		return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "launch root is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}
	marker := filepath.Join(root, codexDesktopRootMarker)
	if err := writePrivateFile(marker, []byte(codexDesktopRootMarkerContent)); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return validateCodexDesktopRoot(root)
}

func validateCodexDesktopRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return domain.NewError(domain.ErrInvalidContract, "validate Codex Desktop launch root", "launch root permissions or type are unsafe")
	}
	marker := filepath.Join(root, codexDesktopRootMarker)
	markerInfo, err := os.Lstat(marker)
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm() != 0o600 {
		return domain.NewError(domain.ErrInvalidContract, "validate Codex Desktop launch root", "launch root ownership marker is unsafe")
	}
	payload, err := os.ReadFile(marker)
	if err != nil || string(payload) != codexDesktopRootMarkerContent {
		return domain.NewError(domain.ErrInvalidContract, "validate Codex Desktop launch root", "launch root ownership could not be verified")
	}
	return nil
}

// ResetCodexDesktopLaunchRoot removes only session directories carrying the
// AgentVeil ownership marker. Unrecognized entries are left untouched.
func ResetCodexDesktopLaunchRoot(root string) error {
	if err := ensureCodexDesktopRoot(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "session-") {
			continue
		}
		home := filepath.Join(root, entry.Name())
		if payload, readErr := os.ReadFile(filepath.Join(home, codexDesktopMarker)); readErr == nil && string(payload) == "agentveil-codex-desktop-v1\n" {
			if err := cleanupCodexDesktopHome(home); err != nil {
				return err
			}
		}
	}
	return nil
}

func clearSensitiveBytes(payload []byte) {
	for index := range payload {
		payload[index] = 0
	}
}
