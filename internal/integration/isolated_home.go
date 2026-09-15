package integration

import (
	"errors"
	"os"
	"runtime"
	"strings"
)

// isolatedHomeDirectory identifies mutable directories that an agent or one of
// its tools may register as a sandbox writable root. These must be real
// directories inside the protected home: linking them to the source home makes
// sandbox setup fail before terminal, patch, browser, or UI tools can start.
func isolatedHomeDirectory(name string) bool {
	switch strings.ToLower(name) {
	case "visualizations", "generated_images", "attachments", "cache", "log", "logs", "browser", "computer-use", "node_repl", "shell_snapshots", ".tmp", "tmp":
		return true
	default:
		return false
	}
}

// persistentIsolatedHomeDirectory is the subset containing user-visible
// artifacts. Codex Desktop keeps these in its stable AgentVeil-owned home when
// a protected launch is retired; caches and runtime scratch state are removed.
func persistentIsolatedHomeDirectory(name string) bool {
	switch strings.ToLower(name) {
	case "visualizations", "generated_images", "attachments":
		return true
	default:
		return false
	}
}

func ensureIsolatedHomeDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return errors.New("isolated home directory is unsafe")
	}
	return nil
}
