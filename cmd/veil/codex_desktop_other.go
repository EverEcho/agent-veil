//go:build !darwin

package main

import "errors"

func codexDesktopExecutable() (string, error) {
	return "", errors.New("Codex Desktop protected launch is currently available only on macOS")
}

func ensureCodexDesktopStopped(string) error {
	return errors.New("Codex Desktop protected launch is currently available only on macOS")
}
