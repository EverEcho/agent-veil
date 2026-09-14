//go:build darwin || linux

package main

import (
	"os/exec"
	"runtime"
)

func openBrowserURL(target string) error {
	command := "xdg-open"
	if runtime.GOOS == "darwin" {
		command = "open"
	}
	return exec.Command(command, target).Start()
}
