//go:build windows

package desktopapp

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	windowsDetachedProcess       = 0x00000008
	windowsCreateNewProcessGroup = 0x00000200
)

func configureCoreCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windowsDetachedProcess | windowsCreateNewProcessGroup, HideWindow: true}
}

func stopCoreProcess(process *os.Process) error { return process.Kill() }

func syncDirectory(string) error { return nil }
