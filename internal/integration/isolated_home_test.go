package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSandboxWritableHomeDirectoryClassification(t *testing.T) {
	for _, name := range []string{"visualizations", "generated_images", "attachments", "cache", "log", "browser", "computer-use", "node_repl", "shell_snapshots", ".tmp", "tmp"} {
		if !isolatedHomeDirectory(name) {
			t.Fatalf("sandbox writable directory %q was not isolated", name)
		}
	}
	for _, name := range []string{"sessions", "archived_sessions", "skills", "thread_history_1.sqlite"} {
		if isolatedHomeDirectory(name) {
			t.Fatalf("canonical persistent state %q was incorrectly isolated", name)
		}
	}
}

func TestEnsureIsolatedHomeDirectoryRejectsSymlinkAndUnsafePermissions(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if err := ensureIsolatedHomeDirectory(linked); err == nil {
		t.Fatal("symlinked sandbox writable directory was accepted")
	}
	if runtime.GOOS != "windows" {
		unsafe := filepath.Join(root, "unsafe")
		if err := os.Mkdir(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := ensureIsolatedHomeDirectory(unsafe); err == nil {
			t.Fatal("group/world-writable sandbox directory was accepted")
		}
	}
}
