//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package discovery

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureVersionCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return killVersionProcessGroup(command) }
}

func cleanupVersionCommand(command *exec.Cmd) {
	_ = killVersionProcessGroup(command)
}

func killVersionProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
