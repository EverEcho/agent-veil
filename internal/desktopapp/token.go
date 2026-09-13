package desktopapp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const desktopTokenFile = "desktop.token"

// LoadOrCreateToken persists the desktop-to-Core management capability in the
// user's private AgentVeil directory so a crashed desktop can safely re-adopt
// the Core it started. Native keychain storage can replace this adapter later.
func LoadOrCreateToken(configDir string) (string, error) {
	if !filepath.IsAbs(configDir) {
		return "", errors.New("desktop token directory must be absolute")
	}
	if err := ensurePrivateDirectory(configDir); err != nil {
		return "", err
	}
	path := filepath.Join(configDir, desktopTokenFile)
	if token, err := readPrivateToken(path); err == nil {
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", errors.New("generate desktop management token")
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	for index := range secret {
		secret[index] = 0
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return readPrivateToken(path)
	}
	if err != nil {
		return "", err
	}
	if _, err := file.WriteString(token + "\n"); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := syncDirectory(configDir); err != nil {
		return "", err
	}
	return token, nil
}

func readPrivateToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 33 || info.Size() > 4097 {
		return "", errors.New("desktop management token file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", errors.New("desktop management token changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4098))
	if err != nil || len(payload) < 33 || len(payload) > 4097 || payload[len(payload)-1] != '\n' {
		return "", errors.New("desktop management token is invalid")
	}
	token := string(payload[:len(payload)-1])
	if len(token) < 32 || len(token) > 4096 {
		return "", errors.New("desktop management token is invalid")
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return "", errors.New("desktop management token is invalid")
		}
	}
	return token, nil
}
