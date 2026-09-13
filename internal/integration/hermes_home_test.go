package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrepareHermesHomeIsolatesConfigurationAndLinksState(t *testing.T) {
	source := t.TempDir()
	if err := os.Chmod(source, 0o700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("model: original\n")
	if err := os.WriteFile(filepath.Join(source, "config.yaml"), originalConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, ".env"), []byte("SECRET=preserved\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rewritten := []byte("model:\n  provider: protected\n")
	home, cleanup, err := PrepareHermesHome(source, rewritten)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	if home == source {
		t.Fatal("temporary Hermes home aliases the source")
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("temporary home mode=%v", info.Mode().Perm())
	}
	content, err := os.ReadFile(filepath.Join(home, "config.yaml"))
	if err != nil || string(content) != string(rewritten) {
		t.Fatalf("temporary config=%q err=%v", content, err)
	}
	configInfo, err := os.Lstat(filepath.Join(home, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if configInfo.Mode()&os.ModeSymlink != 0 || configInfo.Mode().Perm() != 0o600 {
		t.Fatalf("temporary config mode=%v", configInfo.Mode())
	}
	for _, name := range []string{"sessions", ".env"} {
		linked, err := os.Readlink(filepath.Join(home, name))
		if err != nil || linked != filepath.Join(source, name) {
			t.Fatalf("state link %q=%q err=%v", name, linked, err)
		}
	}
	original, err := os.ReadFile(filepath.Join(source, "config.yaml"))
	if err != nil || string(original) != string(originalConfig) {
		t.Fatalf("source config changed: %q err=%v", original, err)
	}

	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup is not idempotent: %v", err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("temporary home survived cleanup: %v", err)
	}
}

func TestPrepareHermesHomeRejectsUnsafeInputs(t *testing.T) {
	realHome := t.TempDir()
	linkedHome := filepath.Join(t.TempDir(), "linked-home")
	if err := os.Symlink(realHome, linkedHome); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		home   string
		config []byte
	}{
		{name: "relative home", home: "relative", config: []byte("model: x\n")},
		{name: "missing home", home: filepath.Join(t.TempDir(), "missing"), config: []byte("model: x\n")},
		{name: "symlink home", home: linkedHome, config: []byte("model: x\n")},
		{name: "empty config", home: t.TempDir()},
		{name: "oversized config", home: t.TempDir(), config: make([]byte, maxHermesConfigBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, cleanup, err := PrepareHermesHome(test.home, test.config); err == nil || cleanup != nil {
				t.Fatalf("unsafe input accepted: cleanup=%v err=%v", cleanup != nil, err)
			}
		})
	}
}

func TestPrepareHermesHomeRejectsGroupOrWorldWritableSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX group/world mode bits")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := PrepareHermesHome(home, []byte("model: protected\n")); err == nil || cleanup != nil {
		t.Fatalf("writable source home accepted: cleanup=%v error=%v", cleanup != nil, err)
	}
}

func TestPrepareHermesHomeRejectsEntryCapacityBeforeCreatingTemporaryState(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxHermesHomeEntries; index++ {
		if err := os.WriteFile(filepath.Join(home, fmt.Sprintf("entry-%04d", index)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, cleanup, err := PrepareHermesHome(home, []byte("model: protected\n")); err == nil || cleanup != nil {
		t.Fatalf("oversized Hermes home accepted: cleanup=%v error=%v", cleanup != nil, err)
	}
}

func TestProtectedHermesHomeCopiesCredentialsAndPinsRuntimeEnvironment(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("OPENAI_API_KEY=provider-secret\nHERMES_CODEX_BASE_URL=https://bypass.example\nHERMES_IGNORE_USER_CONFIG=1\n")
	if err := os.WriteFile(filepath.Join(home, ".env"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	authOriginal := []byte(`{"providers":{"openai-codex":{"tokens":{"access_token":"provider-token"}}},"credential_pool":{"openai-codex":[{"access_token":"provider-token","source":"device_code","base_url":"https://chatgpt.com/backend-api/codex"}]}}`)
	if err := os.WriteFile(filepath.Join(home, "auth.json"), authOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	overrides := map[string]string{
		"HERMES_CODEX_BASE_URL":     "http://127.0.0.1:9191/route/primary/v1",
		"HERMES_IGNORE_USER_CONFIG": "0",
		"HERMES_INFERENCE_PROVIDER": "",
	}
	protected, cleanup, err := prepareHermesHome(home, []byte("model: protected\n"), overrides)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	path := filepath.Join(protected, ".env")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("protected .env mode=%v", info.Mode())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "OPENAI_API_KEY=provider-secret") || !strings.HasSuffix(text, "HERMES_INFERENCE_PROVIDER=\n") || strings.LastIndex(text, "HERMES_CODEX_BASE_URL=http://127.0.0.1:9191/route/primary/v1") < strings.LastIndex(text, "HERMES_CODEX_BASE_URL=https://bypass.example") || strings.LastIndex(text, "HERMES_IGNORE_USER_CONFIG=0") < strings.LastIndex(text, "HERMES_IGNORE_USER_CONFIG=1") {
		t.Fatalf("protected environment overrides were not appended safely: %q", text)
	}
	source, err := os.ReadFile(filepath.Join(home, ".env"))
	if err != nil || string(source) != string(original) {
		t.Fatalf("source environment changed: %q err=%v", source, err)
	}
	protectedAuth, err := os.ReadFile(filepath.Join(protected, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(protectedAuth), `"access_token":"provider-token"`) || !strings.Contains(string(protectedAuth), `"base_url":"http://127.0.0.1:9191/route/primary/v1"`) || !strings.Contains(string(protectedAuth), `"source":"manual:device_code"`) || !strings.Contains(string(protectedAuth), `"suppressed_sources":{"openai-codex":["device_code"]}`) || strings.Contains(string(protectedAuth), `"base_url":"https://chatgpt.com/backend-api/codex"`) {
		t.Fatal("temporary Codex auth route was not rewritten without losing its token")
	}
	protectedAuthInfo, err := os.Lstat(filepath.Join(protected, "auth.json"))
	if err != nil || protectedAuthInfo.Mode()&os.ModeSymlink != 0 || protectedAuthInfo.Mode().Perm() != 0o600 {
		t.Fatalf("protected auth file mode is unsafe: %v err=%v", protectedAuthInfo.Mode(), err)
	}
	sourceAuth, err := os.ReadFile(filepath.Join(home, "auth.json"))
	if err != nil || string(sourceAuth) != string(authOriginal) {
		t.Fatal("source Codex authentication state changed")
	}
}

func TestRewriteHermesCodexAuthRejectsMissingPool(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`{"providers":{"openai-codex":{"tokens":{"access_token":"token"}}}}`),
		[]byte(`{"credential_pool":{"openai-codex":[]}}`),
		[]byte(`{"credential_pool":{"openai-codex":[{"source":"device_code"}]}}`),
	} {
		if _, err := rewriteHermesCodexAuth(content, "http://127.0.0.1:9191/route/primary/v1"); err == nil {
			t.Fatalf("unsafe Codex auth state accepted: %s", content)
		}
	}
}
