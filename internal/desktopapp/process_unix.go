//go:build !windows

package desktopapp

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureCoreCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func stopCoreProcess(process *os.Process) error {
	err := process.Signal(syscall.SIGTERM)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
