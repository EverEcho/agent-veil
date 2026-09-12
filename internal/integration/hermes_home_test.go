package integration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareHermesHomeIsolatesConfigurationAndLinksState(t *testing.T) {
	source := t.TempDir()
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
	for _, test := range []struct {
		name   string
		home   string
		config []byte
	}{
		{name: "relative home", home: "relative", config: []byte("model: x\n")},
		{name: "missing home", home: filepath.Join(t.TempDir(), "missing"), config: []byte("model: x\n")},
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
