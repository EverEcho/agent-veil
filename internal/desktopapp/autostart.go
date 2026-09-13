package desktopapp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type AutoStart struct {
	GOOS string
	Home string
}

func DefaultAutoStart() (AutoStart, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return AutoStart{}, errors.New("user home directory is unavailable")
	}
	return AutoStart{GOOS: runtime.GOOS, Home: home}, nil
}

func (a AutoStart) Enabled() bool {
	path, err := a.path()
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func (a AutoStart) Set(enabled bool, executable string) error {
	path, err := a.path()
	if err != nil {
		return err
	}
	if !enabled {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	if !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\x00\r\n") {
		return errors.New("desktop executable path is invalid")
	}
	payload, mode, err := a.payload(executable)
	if err != nil {
		return err
	}
	return writeAtomic(path, payload, mode)
}

func (a AutoStart) path() (string, error) {
	if !filepath.IsAbs(a.Home) {
		return "", errors.New("autostart home directory must be absolute")
	}
	switch a.GOOS {
	case "linux":
		return filepath.Join(a.Home, ".config", "autostart", "agentveil.desktop"), nil
	case "darwin":
		return filepath.Join(a.Home, "Library", "LaunchAgents", "com.agentveil.desktop.plist"), nil
	case "windows":
		return filepath.Join(a.Home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "AgentVeil.cmd"), nil
	default:
		return "", fmt.Errorf("autostart is unsupported on %s", a.GOOS)
	}
}

func (a AutoStart) payload(executable string) ([]byte, os.FileMode, error) {
	switch a.GOOS {
	case "linux":
		quoted := strings.ReplaceAll(strings.ReplaceAll(executable, `\`, `\\`), `"`, `\"`)
		return []byte("[Desktop Entry]\nType=Application\nVersion=1.0\nName=AgentVeil\nComment=Local privacy control plane\nExec=\"" + quoted + "\"\nTerminal=false\nX-GNOME-Autostart-enabled=true\n\n"), 0o600, nil
	case "darwin":
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(executable)); err != nil {
			return nil, 0, err
		}
		return []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>com.agentveil.desktop</string><key>ProgramArguments</key><array><string>" + escaped.String() + "</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><false/></dict></plist>\n"), 0o600, nil
	case "windows":
		if strings.ContainsAny(executable, "%!^&|<>") {
			return nil, 0, errors.New("desktop executable path cannot be represented safely in a startup command")
		}
		return []byte("@echo off\r\nstart \"\" \"" + strings.ReplaceAll(executable, `"`, `""`) + "\"\r\n"), 0o600, nil
	default:
		return nil, 0, fmt.Errorf("autostart is unsupported on %s", a.GOOS)
	}
}

func writeAtomic(path string, payload []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".agentveil-autostart-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}
