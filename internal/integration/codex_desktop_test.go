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
	if err := os.WriteFile(filepath.Join(source, "thread_history_1.sqlite"), []byte("existing conversations"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sessions", "existing.jsonl"), []byte("existing session"), 0o600); err != nil {
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
	if plan.Executable != executable || home == "" || !strings.HasPrefix(home, launches+string(filepath.Separator)) {
		t.Fatalf("plan=%+v", plan)
	}
	config, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"127.0.0.1:9191/route/primary/v1", "supports_websockets = false", "enable_request_compression = false", "features.apps = false", "env_http_headers"} {
		if !strings.Contains(string(config), required) {
			t.Fatalf("config missing %q: %s", required, config)
		}
	}
	sourceHistory, err := os.Stat(filepath.Join(source, "thread_history_1.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	protectedHistory, err := os.Stat(filepath.Join(home, "thread_history_1.sqlite"))
	if err != nil || !os.SameFile(sourceHistory, protectedHistory) {
		t.Fatalf("existing conversation database was not shared: %v", err)
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
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("temporary home remains: %v", err)
	}
	sourceSession, err := os.ReadFile(filepath.Join(source, "sessions", "existing.jsonl"))
	if err != nil || string(sourceSession) != "existing session" {
		t.Fatalf("source session history changed during cleanup: %q %v", sourceSession, err)
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
	if err := cleanupCodexDesktopHome(directory); err == nil {
		t.Fatal("unknown directory was removed")
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("unknown directory changed: %v", err)
	}
}

func TestResetCodexDesktopLaunchRootRemovesOwnedResidueOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "launches")
	if err := ensureCodexDesktopRoot(root); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(root, "session-owned")
	foreign := filepath.Join(root, "session-foreign")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, codexDesktopMarker), []byte("agentveil-codex-desktop-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "runtime-created-file"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ResetCodexDesktopLaunchRoot(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("owned residue remains: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign directory changed: %v", err)
	}
}
