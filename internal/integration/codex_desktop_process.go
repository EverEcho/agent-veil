package integration

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
)

const maxCodexDesktopBundleBytes = 512 << 20

// CheckCodexDesktopProcessOverride verifies that this installed desktop build
// maps a process-local environment variable to the bundled app-server config.
// An unknown build must not be marked protected merely because it launched.
func CheckCodexDesktopProcessOverride(executable string) error {
	if !filepath.IsAbs(executable) || filepath.Base(executable) != "ChatGPT" || filepath.Base(filepath.Dir(executable)) != "MacOS" {
		return domain.NewError(domain.ErrInvalidContract, "verify Codex Desktop", "official desktop executable path is invalid")
	}
	bundle := filepath.Join(filepath.Dir(filepath.Dir(executable)), "Resources", "app.asar")
	info, err := os.Lstat(bundle)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxCodexDesktopBundleBytes {
		return domain.NewError(domain.ErrInvalidContract, "verify Codex Desktop", "desktop bundle could not be inspected")
	}
	file, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer file.Close()
	markers := [][]byte{
		[]byte("configKey:`openai_base_url`,envVar:`CODEX_APP_SERVER_OPENAI_BASE_URL`"),
		[]byte("CODEX_APP_SERVER_FORCE_CLI"),
		[]byte("CODEX_CLI_PATH"),
	}
	found := make([]bool, len(markers))
	buffer := make([]byte, 64<<10)
	previous := []byte(nil)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			window := append(previous, buffer[:count]...)
			for index, marker := range markers {
				found[index] = found[index] || bytes.Contains(window, marker)
			}
			keep := len(markers[0])
			if len(window) > keep {
				window = window[len(window)-keep:]
			}
			previous = append(previous[:0], window...)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	for _, present := range found {
		if !present {
			return domain.NewError(domain.ErrInvalidContract, "verify Codex Desktop", "this desktop build does not expose the verified process-local model route")
		}
	}
	return nil
}

// PrepareCodexDesktopProcessLaunch keeps the official Codex home and its
// built-in openai provider. Only the child process receives Veil's model URL.
func PrepareCodexDesktopProcessLaunch(agent domain.AgentInstance, desktopExecutable, sourceHome, baseURL string, args []string, coreEndpoint, sessionID, routeToken string) (LaunchPlan, error) {
	if agent.Kind != "codex-desktop" {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "agent kind is not Codex Desktop")
	}
	plan, err := PrepareLaunch(agent, args, coreEndpoint, sessionID, "", routeToken)
	if err != nil {
		return LaunchPlan{}, err
	}
	if !filepath.IsAbs(desktopExecutable) || !filepath.IsAbs(sourceHome) || strings.ContainsRune(desktopExecutable, 0) || strings.ContainsRune(sourceHome, 0) {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "desktop executable and Codex home must be absolute")
	}
	executableInfo, err := os.Lstat(desktopExecutable)
	if err != nil || !executableInfo.Mode().IsRegular() {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "official desktop executable was not found")
	}
	bundledCodex := filepath.Join(filepath.Dir(filepath.Dir(desktopExecutable)), "Resources", "codex")
	bundledInfo, bundledErr := os.Lstat(bundledCodex)
	if bundledErr != nil || !bundledInfo.Mode().IsRegular() || bundledInfo.Mode().Perm()&0o111 == 0 {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "bundled Codex app server was not found")
	}
	homeInfo, err := os.Lstat(sourceHome)
	if err != nil || !homeInfo.IsDir() {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "Codex home was not found")
	}
	parsedURL, err := url.Parse(baseURL)
	coreURL, coreErr := url.Parse(coreEndpoint)
	if err != nil || coreErr != nil || parsedURL.Scheme != "http" || parsedURL.Host != coreURL.Host || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || !validCodexCapabilityBasePath(parsedURL.Path, sessionID, routeToken) {
		return LaunchPlan{}, domain.NewError(domain.ErrInvalidContract, "prepare Codex Desktop launch", "protected model route is invalid")
	}
	plan.Executable = desktopExecutable
	plan.Environment["CODEX_HOME"] = sourceHome
	plan.Environment["OPENAI_BASE_URL"] = baseURL
	plan.Environment["CODEX_APP_SERVER_OPENAI_BASE_URL"] = baseURL
	plan.Environment["CODEX_APP_SERVER_FORCE_CLI"] = "1"
	plan.Environment["CODEX_CLI_PATH"] = bundledCodex
	return plan, nil
}

func validCodexCapabilityBasePath(path, sessionID, routeToken string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 5 && parts[0] == "" && parts[1] == "route" && parts[2] != "" && parts[3] == "__veil" && parts[4] == veilproxy.EncodeCapability(sessionID, routeToken)
}
