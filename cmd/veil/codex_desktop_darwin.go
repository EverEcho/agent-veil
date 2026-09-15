//go:build darwin

package main

import (
	"errors"
	"os/exec"
	"regexp"
)

const officialCodexDesktopExecutable = "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"

func codexDesktopExecutable() (string, error) {
	if _, err := exec.LookPath(officialCodexDesktopExecutable); err != nil {
		return "", errors.New("未找到官方 Codex 桌面客户端 /Applications/ChatGPT.app")
	}
	return officialCodexDesktopExecutable, nil
}

func ensureCodexDesktopStopped(executable string) error {
	for _, pattern := range codexDesktopProcessPatterns(executable) {
		err := exec.Command("/usr/bin/pgrep", "-f", pattern).Run()
		if err == nil {
			return errors.New("Codex 桌面客户端仍在运行；请从 Codex 菜单完全退出，等待几秒后重试")
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
			continue
		}
		return errors.New("无法安全确认 Codex 桌面客户端是否正在运行")
	}
	return nil
}

func codexDesktopProcessPatterns(executable string) []string {
	// macOS pgrep uses POSIX ERE. Keep the group capturing: non-capturing
	// groups such as (?:...) are a syntax error rather than a no-match result.
	// A standalone bundled `codex app-server` is not sufficient evidence that
	// the desktop application is open: Codex development tools use the same
	// binary independently. Only the real GUI main process blocks relaunch.
	return []string{"^" + regexp.QuoteMeta(executable) + "( |$)"}
}
