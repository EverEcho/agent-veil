package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestPrepareCodexDesktopLaunchUsesIsolatedHomeAndPreservesSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	launches := filepath.Join(root, "launches")
	executable := filepath.Join(root, "ChatGPT")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "auth.json"), []byte(`{"auth_mode":"chatgpt","token":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config.toml"), []byte("model = \"original\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"thread_history_1.sqlite":     "existing conversations",
		"thread_history_1.sqlite-wal": "existing write-ahead log",
		"thread_history_1.sqlite-shm": "existing shared memory",
	} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(source, "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sessions", "existing.jsonl"), []byte("existing session"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "archived_sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "archived_sessions", "archived.jsonl"), []byte("archived session"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "visualizations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "visualizations", "source-artifact"), []byte("source artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "ipc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	agent := domain.AgentInstance{ID: "codex-desktop-local", Kind: "codex-desktop", Version: "0.154.0", Executable: filepath.Join(root, "codex"), Mode: domain.ModeLaunch}
	if err := os.WriteFile(agent.Executable, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareCodexDesktopLaunch(agent, executable, source, launches, "http://127.0.0.1:9191/route/primary/v1", false, nil, "http://127.0.0.1:9191", "session-0123456789", strings.Repeat("t", 32))
	if err != nil {
		t.Fatal(err)
	}
	home := plan.Environment["CODEX_HOME"]
	if plan.Executable != executable || home != filepath.Join(launches, "home") {
		t.Fatalf("plan=%+v", plan)
	}
	config, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"model_provider = \"agentveil\"", "127.0.0.1:9191/route/primary/v1", "supports_websockets = false", "requires_openai_auth = true", "enable_request_compression = false", "features.apps = false", "env_http_headers"} {
		if !strings.Contains(string(config), required) {
			t.Fatalf("config missing %q: %s", required, config)
		}
	}
	if strings.Contains(string(config), "openai_base_url") {
		t.Fatalf("config uses the WebSocket-capable built-in provider: %s", config)
	}
	if strings.Contains(string(config), "allow_symlinked_codex_home") {
		t.Fatalf("config weakened symlinked writable-root protection: %s", config)
	}
	sourceHistory, err := os.Stat(filepath.Join(source, "thread_history_1.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	protectedHistory, err := os.Stat(filepath.Join(home, "thread_history_1.sqlite"))
	if err != nil || !os.SameFile(sourceHistory, protectedHistory) {
		t.Fatalf("existing conversation database was not shared: %v", err)
	}
	for _, name := range []string{"thread_history_1.sqlite", "thread_history_1.sqlite-wal", "thread_history_1.sqlite-shm"} {
		if linkedHistory, err := os.Lstat(filepath.Join(home, name)); err != nil || linkedHistory.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("conversation database state %s must use one canonical symlinked path: %v %v", name, linkedHistory, err)
		}
	}
	visualizations := filepath.Join(home, "visualizations")
	if info, err := os.Lstat(visualizations); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("sandbox writable visualizations directory was not isolated: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(visualizations, "source-artifact")); !os.IsNotExist(err) {
		t.Fatalf("source visualization state leaked into isolated home: %v", err)
	}
	if err := os.WriteFile(filepath.Join(visualizations, "protected-artifact"), []byte("protected artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if linked, err := os.ReadFile(filepath.Join(home, "sessions", "existing.jsonl")); err != nil || string(linked) != "existing session" {
		t.Fatalf("existing session history is unavailable: %q error=%v", linked, err)
	}
	if _, err := os.Lstat(filepath.Join(home, "ipc")); !os.IsNotExist(err) {
		t.Fatalf("runtime IPC was shared into protected launch: %v", err)
	}
	if err := plan.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "auth.json")); !os.IsNotExist(err) {
		t.Fatalf("authentication remained in retired home: %v", err)
	}
	if payload, err := os.ReadFile(filepath.Join(home, codexDesktopMarker)); err != nil || string(payload) != codexDesktopRetiredMarkerContent {
		t.Fatalf("rollout redirect marker is missing: %q %v", payload, err)
	}
	if artifact, err := os.ReadFile(filepath.Join(home, "visualizations", "protected-artifact")); err != nil || string(artifact) != "protected artifact" {
		t.Fatalf("protected visualization did not survive retirement: %q %v", artifact, err)
	}
	second, err := PrepareCodexDesktopLaunch(agent, executable, source, launches, "http://127.0.0.1:9191/route/primary/v1", false, nil, "http://127.0.0.1:9191", "session-0123456789", strings.Repeat("t", 32))
	if err != nil {
		t.Fatal(err)
	}
	if artifact, err := os.ReadFile(filepath.Join(second.Environment["CODEX_HOME"], "visualizations", "protected-artifact")); err != nil || string(artifact) != "protected artifact" {
		t.Fatalf("protected visualization did not survive relaunch: %q %v", artifact, err)
	}
	if err := second.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(home, "sessions")); err != nil || target != filepath.Join(source, "sessions") {
		t.Fatalf("conversation path was not retained: %q %v", target, err)
	}
	if target, err := os.Readlink(filepath.Join(home, "archived_sessions")); err != nil || target != filepath.Join(source, "archived_sessions") {
		t.Fatalf("archived conversation path was not retained: %q %v", target, err)
	}
	sourceSession, err := os.ReadFile(filepath.Join(source, "sessions", "existing.jsonl"))
	if err != nil || string(sourceSession) != "existing session" {
		t.Fatalf("source session history changed during cleanup: %q %v", sourceSession, err)
	}
	archivedSession, err := os.ReadFile(filepath.Join(home, "archived_sessions", "archived.jsonl"))
	if err != nil || string(archivedSession) != "archived session" {
		t.Fatalf("archived session history is unavailable after cleanup: %q %v", archivedSession, err)
	}
	sourceDatabase, err := os.ReadFile(filepath.Join(source, "thread_history_1.sqlite"))
	if err != nil || string(sourceDatabase) != "existing conversations" {
		t.Fatalf("source conversation database changed during cleanup: %q %v", sourceDatabase, err)
	}
	original, err := os.ReadFile(filepath.Join(source, "config.toml"))
	if err != nil || string(original) != "model = \"original\"\n" {
		t.Fatalf("source changed: %q %v", original, err)
	}
}

func TestCodexDesktopConfigDisablesWebSockets(t *testing.T) {
	config := renderCodexDesktopConfig("http://127.0.0.1:9191/route/primary/v1", false)
	if !strings.Contains(config, `model_provider = "agentveil"`) || !strings.Contains(config, `base_url = "http://127.0.0.1:9191/route/primary/v1"`) || !strings.Contains(config, "supports_websockets = false") || !strings.Contains(config, "requires_openai_auth = true") {
		t.Fatalf("protected provider configuration is invalid: %s", config)
	}
}

func TestCodexDesktopAPIKeyConfigDoesNotRequireStoredLogin(t *testing.T) {
	config := renderCodexDesktopConfig("http://127.0.0.1:9191/route/primary/v1", true)
	if !strings.Contains(config, `env_key = "OPENAI_API_KEY"`) || strings.Contains(config, "requires_openai_auth") {
		t.Fatalf("API-key configuration is invalid: %s", config)
	}
}

func TestCodexDesktopAuthAcceptsOfficialReadPermissionsButRejectsSharedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"auth_mode":"chatgpt"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if payload, found, err := readCodexDesktopAuth(path); err != nil || !found || len(payload) == 0 {
		t.Fatalf("official auth permissions were rejected: found=%v error=%v", found, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCodexDesktopAuth(path); err == nil {
		t.Fatal("auth file writable by other accounts was accepted")
	}
}

func TestCodexDesktopCleanupRefusesUnknownDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := removeOwnedCodexDesktopHome(directory); err == nil {
		t.Fatal("unknown directory was removed")
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("unknown directory changed: %v", err)
	}
}

func TestResetCodexDesktopLaunchRootRetiresOwnedResidueOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "launches")
	if err := ensureCodexDesktopRoot(root); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(root, "session-owned")
	foreign := filepath.Join(root, "session-foreign")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, codexDesktopMarker), []byte(codexDesktopUpgradeMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "runtime-created-file"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceSessions := filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(sourceSessions, 0o700); err != nil {
		t.Fatal(err)
	}
	sourceArchivedSessions := filepath.Join(t.TempDir(), "archived_sessions")
	if err := os.Mkdir(sourceArchivedSessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sourceSessions, filepath.Join(owned, "sessions")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sourceArchivedSessions, filepath.Join(owned, "archived_sessions")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ResetCodexDesktopLaunchRoot(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(owned, "runtime-created-file")); !os.IsNotExist(err) {
		t.Fatalf("runtime residue remains: %v", err)
	}
	if payload, err := os.ReadFile(filepath.Join(owned, codexDesktopMarker)); err != nil || string(payload) != codexDesktopRetiredMarkerContent {
		t.Fatalf("owned launch was not retired: %q %v", payload, err)
	}
	if target, err := os.Readlink(filepath.Join(owned, "sessions")); err != nil || target != sourceSessions {
		t.Fatalf("retired rollout path is invalid: %q %v", target, err)
	}
	if target, err := os.Readlink(filepath.Join(owned, "archived_sessions")); err != nil || target != sourceArchivedSessions {
		t.Fatalf("retired archived rollout path is invalid: %q %v", target, err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign directory changed: %v", err)
	}
}
