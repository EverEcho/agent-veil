package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/domain"
)

func TestCodexDesktopProcessLaunchPreservesOriginalHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "codex-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"original\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "ChatGPT.app", "Contents", "MacOS", "ChatGPT")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	resources := filepath.Join(root, "ChatGPT.app", "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "app.asar"), []byte("configKey:`openai_base_url`,envVar:`CODEX_APP_SERVER_OPENAI_BASE_URL` CODEX_APP_SERVER_FORCE_CLI CODEX_CLI_PATH"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "codex"), []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckCodexDesktopProcessOverride(executable); err != nil {
		t.Fatal(err)
	}
	agentExecutable := filepath.Join(root, "codex")
	agent := domain.AgentInstance{ID: "codex-desktop-local", Kind: "codex-desktop", Version: "0.155.0", Executable: agentExecutable, Mode: domain.ModeLaunch}
	endpoint := "http://127.0.0.1:9191"
	routeToken := strings.Repeat("t", 64)
	baseURL := endpoint + "/route/primary/__veil/veil-v1:session-0123456789:" + routeToken
	plan, err := PrepareCodexDesktopProcessLaunch(agent, executable, home, baseURL, nil, endpoint, "session-0123456789", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable != executable || plan.Environment["CODEX_HOME"] != home || plan.Environment["CODEX_APP_SERVER_OPENAI_BASE_URL"] != baseURL || plan.Environment["CODEX_APP_SERVER_FORCE_CLI"] != "1" || plan.Environment["CODEX_CLI_PATH"] != filepath.Join(resources, "codex") {
		t.Fatalf("invalid process launch plan: %+v", plan)
	}
	if err := plan.Cleanup(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 1 || entries[0].Name() != "config.toml" {
		t.Fatalf("process launch modified original home: %v %v", entries, err)
	}
	if content, err := os.ReadFile(configPath); err != nil || string(content) != "model = \"original\"\n" {
		t.Fatalf("process launch modified original config: %q %v", content, err)
	}
}

func TestCodexDesktopProcessLaunchRejectsUnknownBundleAndOffLoopbackRoute(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "ChatGPT.app", "Contents", "MacOS", "ChatGPT")
	resources := filepath.Join(root, "ChatGPT.app", "Contents", "Resources")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resources, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "app.asar"), []byte("unknown app"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckCodexDesktopProcessOverride(executable); err == nil {
		t.Fatal("unknown desktop build was accepted")
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	agent := domain.AgentInstance{ID: "codex-desktop-local", Kind: "codex-desktop", Executable: filepath.Join(root, "codex"), Mode: domain.ModeLaunch}
	if _, err := PrepareCodexDesktopProcessLaunch(agent, executable, home, "https://example.com/route/primary/__veil/token", nil, "http://127.0.0.1:9191", "session-0123456789", strings.Repeat("t", 64)); err == nil {
		t.Fatal("off-loopback model route was accepted")
	}
}
