package integration

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
)

const codexDesktopMarker = ".agentveil-codex-desktop-launch"
const codexDesktopRootMarker = ".agentveil-owned-codex-desktop-root"
const codexDesktopRootMarkerContent = "agentveil-codex-desktop-root-v1\n"
const codexDesktopActiveMarkerContent = "agentveil-codex-desktop-v1\n"
const codexDesktopUpgradeMarkerContent = "agentveil-codex-desktop-preserve-for-upgrade-v1\n"
const codexDesktopRetiredMarkerContent = "agentveil-codex-desktop-rollout-link-v1\n"
const maxCodexDesktopAuthBytes = 8 << 20
const maxCodexDesktopHomeEntries = 4096

// PrepareCodexDesktopLaunch creates an isolated Codex home for the official
// desktop application. The user's Codex configuration is never modified.
func PrepareCodexDesktopLaunch(agent domain.AgentInstance, desktopExecutable, sourceHome, protectedRoot, baseURL string, args []string, coreEndpoint, sessionID, routeToken string) (LaunchPlan, error) {
	if agent.Kind != "codex-desktop" {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "agent kind is not Codex Desktop")
	}
	plan, err := PrepareLaunch(agent, args, coreEndpoint, sessionID, "", routeToken)
	if err != nil {
		return LaunchPlan{}, err
	}
	if !filepath.IsAbs(desktopExecutable) || strings.ContainsRune(desktopExecutable, 0) || !filepath.IsAbs(sourceHome) || !filepath.IsAbs(protectedRoot) {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "desktop executable and launch directories must be absolute")
	}
	info, err := os.Lstat(desktopExecutable)
	if err != nil || !info.Mode().IsRegular() {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "official desktop executable was not found")
	}
	if err := ensureCodexDesktopRoot(protectedRoot); err != nil {
		return LaunchPlan{}, err
	}
	protectedHome := filepath.Join(protectedRoot, "home")
	if err := initializeCodexDesktopHome(protectedHome); err != nil {
		return LaunchPlan{}, err
	}
	cleanup := func() error { return cleanupCodexDesktopLaunchHome(protectedHome) }
	fail := func(cause error) (LaunchPlan, error) {
		return LaunchPlan{}, errors.Join(cause, cleanup())
	}
	if err := writePrivateFile(filepath.Join(protectedHome, codexDesktopMarker), []byte(codexDesktopActiveMarkerContent)); err != nil {
		return fail(err)
	}
	if err := linkCodexDesktopState(sourceHome, protectedHome); err != nil {
		return fail(err)
	}
	config := renderCodexDesktopConfig(baseURL, sessionID, routeToken)
	if err := writePrivateFile(filepath.Join(protectedHome, "config.toml"), []byte(config)); err != nil {
		return fail(err)
	}
	auth, found, err := readCodexDesktopAuth(filepath.Join(sourceHome, "auth.json"))
	if err != nil {
		return fail(err)
	}
	if found {
		defer clearSensitiveBytes(auth)
		if err := writePrivateFile(filepath.Join(protectedHome, "auth.json"), auth); err != nil {
			return fail(err)
		}
	}
	plan.Executable = desktopExecutable
	plan.Environment["CODEX_HOME"] = protectedHome
	plan.cleanup = cleanup
	return plan, nil
}

// linkCodexDesktopState exposes the user's existing conversations and normal
// desktop state inside the isolated launch home without sharing configuration
// or credentials. Persistent state uses a symlink so Codex and SQLite resolve
// one canonical path for database, WAL, shared-memory and lock coordination.
// Directories that tools may register as sandbox writable roots are instead
// materialized inside the protected home. Hard-linking a live SQLite database
// under another path creates a second WAL and lock namespace and can corrupt
// the shared history database.
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
		if isolatedHomeDirectory(name) {
			if err := ensureIsolatedHomeDirectory(filepath.Join(temporaryHome, name)); err != nil {
				return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "sandbox writable state could not be isolated")
			}
			continue
		}
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
		case info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().IsRegular():
			err = os.Symlink(source, destination)
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

func renderCodexDesktopConfig(baseURL, sessionID, routeToken string) string {
	capabilityBaseURL := strings.TrimRight(baseURL, "/") + "/__veil/" + url.PathEscape(veilproxy.EncodeCapability(sessionID, routeToken))
	return fmt.Sprintf(`model_provider = "openai"
openai_base_url = %q
features.enable_request_compression = false
features.apps = false
`, capabilityBaseURL)
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

func initializeCodexDesktopHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Base(home) != "home" {
		return domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "stable home path is invalid")
	}
	if _, err := os.Lstat(home); err == nil {
		if err := resetOwnedCodexDesktopHome(home); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		return os.Mkdir(home, 0o700)
	}
	return nil
}

// resetOwnedCodexDesktopHome removes configuration, credentials, links, and
// runtime state from an owned launch home while retaining safe, real
// user-artifact directories. Non-directory entries are removed without being
// followed.
func resetOwnedCodexDesktopHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Base(home) == "." {
		return domain.NewError(domain.ErrInvalidContract, "reset Codex Desktop launch", "temporary home is invalid")
	}
	marker := filepath.Join(home, codexDesktopMarker)
	payload, err := os.ReadFile(marker)
	if err != nil || string(payload) != codexDesktopActiveMarkerContent && string(payload) != codexDesktopUpgradeMarkerContent && string(payload) != codexDesktopRetiredMarkerContent {
		return domain.NewError(domain.ErrInvalidContract, "reset Codex Desktop launch", "temporary home ownership could not be verified")
	}
	if err := validateCodexDesktopRoot(filepath.Dir(home)); err != nil {
		return err
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) > maxCodexDesktopHomeEntries {
		return domain.NewError(domain.ErrInvalidContract, "reset Codex Desktop launch", "temporary home could not be enumerated safely")
	}
	for _, entry := range entries {
		path := filepath.Join(home, entry.Name())
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return domain.NewError(domain.ErrInvalidContract, "reset Codex Desktop launch", "temporary home changed during reset")
		}
		if persistentIsolatedHomeDirectory(entry.Name()) && info.IsDir() {
			if runtime.GOOS == "windows" || info.Mode().Perm()&0o022 == 0 {
				continue
			}
		}
		if err := os.RemoveAll(path); err != nil {
			return domain.NewError(domain.ErrInvalidContract, "reset Codex Desktop launch", "temporary home state could not be removed")
		}
	}
	return os.Chmod(home, 0o700)
}

func removeOwnedCodexDesktopHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Base(home) == "." {
		return domain.NewError(domain.ErrInvalidContract, "clean Codex Desktop launch", "temporary home is invalid")
	}
	marker := filepath.Join(home, codexDesktopMarker)
	payload, err := os.ReadFile(marker)
	if err != nil || string(payload) != codexDesktopActiveMarkerContent && string(payload) != codexDesktopUpgradeMarkerContent && string(payload) != codexDesktopRetiredMarkerContent {
		return domain.NewError(domain.ErrInvalidContract, "clean Codex Desktop launch", "temporary home ownership could not be verified")
	}
	if err := validateCodexDesktopRoot(filepath.Dir(home)); err != nil {
		return err
	}
	return os.RemoveAll(home)
}

func cleanupCodexDesktopLaunchHome(home string) error {
	if _, err := os.Readlink(filepath.Join(home, "sessions")); err == nil {
		return retireCodexDesktopHome(home)
	}
	return removeOwnedCodexDesktopHome(home)
}

// retireCodexDesktopHome removes credentials, configuration and runtime state,
// but keeps the absolute conversation paths alive. Codex stores rollout_path as
// an absolute CODEX_HOME path; deleting either the active or archived path makes
// existing conversations impossible to restore or delete even though the
// rollout file still exists.
func retireCodexDesktopHome(home string) error {
	marker := filepath.Join(home, codexDesktopMarker)
	payload, err := os.ReadFile(marker)
	if err != nil {
		return domain.NewError(domain.ErrInvalidContract, "retire Codex Desktop launch", "launch ownership could not be verified")
	}
	if string(payload) == codexDesktopRetiredMarkerContent {
		return nil
	}
	if string(payload) != codexDesktopActiveMarkerContent && string(payload) != codexDesktopUpgradeMarkerContent {
		return domain.NewError(domain.ErrInvalidContract, "retire Codex Desktop launch", "launch ownership could not be verified")
	}
	sessions := filepath.Join(home, "sessions")
	sourceSessions, err := os.Readlink(sessions)
	if err != nil || !filepath.IsAbs(sourceSessions) || strings.ContainsRune(sourceSessions, 0) {
		return domain.NewError(domain.ErrInvalidContract, "retire Codex Desktop launch", "conversation path is unavailable or unsafe")
	}
	conversationLinks := map[string]string{"sessions": sourceSessions}
	archivedSessions := filepath.Join(home, "archived_sessions")
	if sourceArchivedSessions, archivedErr := os.Readlink(archivedSessions); archivedErr == nil {
		if !filepath.IsAbs(sourceArchivedSessions) || strings.ContainsRune(sourceArchivedSessions, 0) {
			return domain.NewError(domain.ErrInvalidContract, "retire Codex Desktop launch", "archived conversation path is unsafe")
		}
		conversationLinks["archived_sessions"] = sourceArchivedSessions
	} else if !errors.Is(archivedErr, os.ErrNotExist) {
		return domain.NewError(domain.ErrInvalidContract, "retire Codex Desktop launch", "archived conversation path is unavailable or unsafe")
	}
	if err := resetOwnedCodexDesktopHome(home); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(home, codexDesktopMarker), []byte(codexDesktopRetiredMarkerContent)); err != nil {
		return err
	}
	for _, name := range []string{"sessions", "archived_sessions"} {
		target, ok := conversationLinks[name]
		if !ok {
			continue
		}
		if err := os.Symlink(target, filepath.Join(home, name)); err != nil {
			return err
		}
	}
	return nil
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

// ResetCodexDesktopLaunchRoot retires interrupted launch homes without
// removing their rollout paths. Unrecognized entries are left untouched.
func ResetCodexDesktopLaunchRoot(root string) error {
	if err := ensureCodexDesktopRoot(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() != "home" && !strings.HasPrefix(entry.Name(), "session-") {
			continue
		}
		home := filepath.Join(root, entry.Name())
		if payload, readErr := os.ReadFile(filepath.Join(home, codexDesktopMarker)); readErr == nil && (string(payload) == codexDesktopActiveMarkerContent || string(payload) == codexDesktopUpgradeMarkerContent) {
			if err := retireCodexDesktopHome(home); err != nil {
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
