package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/agentveil/agentveil/internal/discovery"
)

const protectedLaunchLease = 30 * time.Second
const protectedLaunchHeartbeat = 10 * time.Second
const managedManifestInterval = time.Second
const maxManagementResponseBytes = 4 << 20
const maxManagementErrorBytes = 4 << 10
const maxHermesLaunchConfigBytes = 1 << 20
const nestedSessionMaxTTL = 24 * time.Hour
const maxModelManifestPayloadBytes = 6 << 10
const modelManagementTimeout = 16 * time.Minute
const maxPolicyDocumentBytes = 1 << 20

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: veil <agents|approvals|audit|calls|compatibility|diagnostics|discover|inspect|models|nested|policy|rules|run|serve|sessions|status|web>")
	}
	switch args[0] {
	case "calls":
		if len(args) != 1 {
			return fmt.Errorf("usage: veil %s", args[0])
		}
		return liveStateCommand(args[0], os.Stdout)
	case "agents":
		return agentsCommand(args[1:], os.Stdout)
	case "sessions":
		return sessionsCommand(args[1:], os.Stdout)
	case "approvals":
		return approvalsCommand(args[1:], os.Stdout)
	case "audit":
		if len(args) != 1 {
			return errors.New("usage: veil audit")
		}
		return auditReport()
	case "serve":
		return serve()
	case "status":
		if len(args) != 1 {
			return errors.New("usage: veil status")
		}
		return status()
	case "web":
		return webCommand(args[1:], os.Stdout, openBrowserURL)
	case "compatibility":
		if len(args) == 2 && args[1] == "--offline" {
			return writeOfflineCompatibilityReport(os.Stdout)
		}
		if len(args) != 1 {
			return errors.New("usage: veil compatibility [--offline]")
		}
		return compatibilityReport()
	case "diagnostics":
		if len(args) != 1 {
			return errors.New("usage: veil diagnostics")
		}
		return diagnostics()
	case "rules":
		return rulesCommand(args[1:], os.Stdout)
	case "models":
		return modelsCommand(args[1:], os.Stdout)
	case "policy":
		return policyCommand(args[1:], os.Stdout)
	case "discover":
		if len(args) != 1 {
			return errors.New("usage: veil discover")
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(discovery.Default().DetectAll(context.Background()))
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: veil inspect <codex|claude|hermes|openclaw|opencode|cursor|zed|cline>")
		}
		manifest, err := discovery.Default().Inspect(context.Background(), args[1])
		if err != nil {
			return err
		}
		return writeInspection(os.Stdout, manifest)
	case "run":
		name, childArgs, interactive, err := parseProtectedRun(args[1:])
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runProtected(ctx, name, childArgs, interactive)
	case "nested":
		name, childArgs, err := parseNestedRun(args[1:])
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runNestedProtected(ctx, name, childArgs)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func webCommand(args []string, writer io.Writer, opener func(string) error) error {
	if writer == nil || opener == nil || len(args) > 1 || len(args) == 1 && args[0] != "--print" {
		return errors.New("usage: veil web [--print]")
	}
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	token, err := webManagementToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticket, err := createBrowserTicket(ctx, endpoint, token)
	if err != nil {
		return err
	}
	target := endpoint + "/#ticket=" + ticket
	if _, err := fmt.Fprintln(writer, target); err != nil {
		return err
	}
	if len(args) == 1 {
		return nil
	}
	return opener(target)
}

func webManagementToken() (string, error) {
	if token := os.Getenv("VEIL_ADMIN_TOKEN"); validWebManagementToken(token) {
		return token, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	file, info, err := openCLIFile(filepath.Join(configDir, "agentveil", "desktop.token"), 4096)
	if err != nil {
		return "", errors.New("Web access requires VEIL_ADMIN_TOKEN or a running AgentVeil Desktop")
	}
	defer file.Close()
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("AgentVeil Desktop token permissions are unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(payload) > 4096 {
		return "", errors.New("AgentVeil Desktop token is unreadable")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(payload), "\n"), "\r")
	if !validWebManagementToken(token) {
		return "", errors.New("AgentVeil Desktop token is invalid")
	}
	return token, nil
}

func validWebManagementToken(value string) bool {
	if len(value) < 32 || len(value) > 4096 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func parseNestedRun(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, errors.New("usage: veil nested <codex|claude> [-- agent arguments]")
	}
	childArgs := append([]string(nil), args[1:]...)
	if len(childArgs) > 0 && childArgs[0] == "--" {
		childArgs = childArgs[1:]
	}
	return args[0], childArgs, nil
}

func parseProtectedRun(args []string) (string, []string, bool, error) {
	if len(args) == 0 {
		return "", nil, false, errors.New("usage: veil run <codex|claude|hermes> [--interactive] [-- agent arguments]")
	}
	name := args[0]
	childArgs := append([]string(nil), args[1:]...)
	interactive := false
	if len(childArgs) > 0 && childArgs[0] == "--interactive" {
		interactive = true
		childArgs = childArgs[1:]
	}
	if len(childArgs) > 0 && childArgs[0] == "--" {
		childArgs = childArgs[1:]
	}
	return name, childArgs, interactive, nil
}
