//go:build darwin

package main

import (
	"errors"
	"os/exec"
	"regexp"
	"time"
)

const officialCodexDesktopExecutable = "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"

func codexDesktopExecutable() (string, error) {
	if _, err := exec.LookPath(officialCodexDesktopExecutable); err != nil {
		return "", errors.New("未找到官方 Codex 桌面客户端 /Applications/ChatGPT.app")
	}
	return officialCodexDesktopExecutable, nil
}

func codexDesktopRunning(executable string) (bool, error) {
	for _, pattern := range codexDesktopProcessPatterns(executable) {
		err := exec.Command("/usr/bin/pgrep", "-f", pattern).Run()
		if err == nil {
			return true, nil
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
			continue
		}
		return false, errors.New("无法安全确认 Codex 桌面客户端是否正在运行")
	}
	return false, nil
}

func stopCodexDesktopForProtectedLaunch(executable string) error {
	running, err := codexDesktopRunning(executable)
	if err != nil || !running {
		return err
	}
	status := exec.Command("/usr/bin/pkill", "-TERM", "-f", codexDesktopProcessPatterns(executable)[0]).Run()
	if status != nil {
		var exitError *exec.ExitError
		if !errors.As(status, &exitError) || exitError.ExitCode() != 1 {
			return errors.New("无法安全关闭原 Codex 桌面客户端")
		}
	}
	for attempt := 0; attempt < 50; attempt++ {
		running, err = codexDesktopRunning(executable)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("原 Codex 桌面客户端未能在 5 秒内退出；请手动退出后重试")
}

func codexDesktopProcessPatterns(executable string) []string {
	// macOS pgrep uses POSIX ERE. Keep the group capturing: non-capturing
	// groups such as (?:...) are a syntax error rather than a no-match result.
	// A standalone bundled `codex app-server` is not sufficient evidence that
	// the desktop application is open: Codex development tools use the same
	// binary independently. Only the real GUI main process blocks relaunch.
	return []string{"^" + regexp.QuoteMeta(executable) + "( |$)"}
}
