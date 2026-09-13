package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/feedback"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/jsonsafe"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/protocol"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
	nativesdk "github.com/agentveil/agentveil/sdk/native"
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

type protectedEgressBinding struct {
	SessionID  string
	AgentID    string
	Generation uint64
	RouteID    string
	AdminToken string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "veil:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: veil <approvals|compatibility|diagnostics|discover|inspect|models|nested|policy|rules|run|serve|status>")
	}
	switch args[0] {
	case "approvals":
		return approvalsCommand(args[1:], os.Stdout)
	case "serve":
		return serve()
	case "status":
		if len(args) != 1 {
			return errors.New("usage: veil status")
		}
		return status()
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

func runProtected(ctx context.Context, name string, childArgs []string, interactive bool) (resultErr error) {
	if name != "codex" && name != "claude" && name != "hermes" {
		return fmt.Errorf("protected launch for %s is not verified", name)
	}
	if name == "hermes" {
		if err := validateHermesProtectedArgs(childArgs); err != nil {
			return err
		}
	}
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	adminToken := os.Getenv("VEIL_ADMIN_TOKEN")
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	if err := requireCompatibleCore(ctx, endpoint, adminToken); err != nil {
		return err
	}
	manifest, err := discovery.Default().Inspect(ctx, name)
	if err != nil {
		return err
	}
	if name == "claude" && (len(manifest.Surfaces) != 1 || manifest.Surfaces[0].Auth.Type != domain.AuthAnthropicKey) {
		return errors.New("protected Claude launch currently requires ANTHROPIC_API_KEY; OAuth mode has no verified capability-header injection")
	}
	var registered registry.Entry
	registration := map[string]any{"manifest": manifest, "ttl_seconds": int64(protectedLaunchLease / time.Second)}
	if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/agents/leases", adminToken, registration, &registered); err != nil {
		return err
	}
	defer func() {
		target := endpoint + "/v1/agents/" + manifest.Agent.ID + "?generation=" + strconv.FormatUint(registered.Generation, 10)
		_ = managementJSON(context.Background(), http.MethodDelete, target, adminToken, nil, nil)
	}()
	protectedRoutes, err := fullyProtectedRoutes(registered)
	if err != nil {
		return err
	}
	if err := writeLaunchProtectionPlan(os.Stderr, registered); err != nil {
		return fmt.Errorf("display protection plan: %w", err)
	}
	if name != "hermes" && len(protectedRoutes) != 1 {
		return errors.New("agent-specific multi-route launch injection is not verified")
	}
	protectedRoute := protectedRoutes[0]
	routeIDs := make([]string, len(protectedRoutes))
	for index, route := range protectedRoutes {
		routeIDs[index] = route.ID
	}
	var created session.Created
	if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/sessions", adminToken, map[string]any{"route_ids": routeIDs, "ttl_seconds": 86400, "interactive": interactive}, &created); err != nil {
		return err
	}
	defer func() {
		_ = managementJSON(context.Background(), http.MethodDelete, endpoint+"/v1/sessions/"+created.Session.ID, adminToken, nil, nil)
	}()
	credentials, err := bindRouteCredentials(protectedRoutes, created)
	if err != nil {
		return err
	}
	routeToken := credentials[protectedRoute.ID]
	var launch integration.LaunchPlan
	if name == "hermes" {
		configPath, pathErr := hermesManifestConfigPath(manifest)
		if pathErr != nil {
			return pathErr
		}
		configContent, readErr := readProtectedHermesConfig(configPath)
		if readErr != nil {
			return readErr
		}
		bindings := make(map[string]integration.HermesRouteBinding, len(protectedRoutes))
		for _, route := range protectedRoutes {
			bindings[route.SurfaceID] = integration.HermesRouteBinding{RouteID: route.ID, Token: credentials[route.ID]}
		}
		rewritten, rewriteErr := integration.RewriteHermesConfig(configContent, endpoint, created.Session.ID, bindings)
		if rewriteErr != nil {
			return rewriteErr
		}
		rewrittenSlots, _, parseErr := integration.ParseHermesConfig(rewritten)
		if parseErr != nil {
			return parseErr
		}
		var primaryBaseURL string
		for _, slot := range rewrittenSlots {
			if slot.ID == "primary" {
				primaryBaseURL = slot.BaseURL
				break
			}
		}
		if primaryBaseURL == "" {
			return errors.New("Hermes protected route set has no primary model")
		}
		runtimeEnvironment := map[string]string{
			"HERMES_CODEX_BASE_URL":     primaryBaseURL,
			"HERMES_IGNORE_USER_CONFIG": "0",
			"HERMES_INFERENCE_PROVIDER": "",
			"HERMES_TUI_PROVIDER":       "",
		}
		launch, err = integration.PrepareHermesLaunch(manifest.Agent, childArgs, endpoint, created.Session.ID, "", routeToken, filepath.Dir(configPath), rewritten, runtimeEnvironment)
	} else {
		launch, err = integration.PrepareLaunch(manifest.Agent, childArgs, endpoint, created.Session.ID, "", routeToken)
	}
	if err != nil {
		return err
	}
	launch.Environment["VEIL_ROUTE_ID"] = protectedRoute.ID
	defer func() {
		if cleanupErr := launch.Cleanup(); cleanupErr != nil && resultErr == nil {
			resultErr = cleanupErr
		}
	}()
	localBypass := localNoProxy(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
	launch.Environment["NO_PROXY"] = localBypass
	launch.Environment["no_proxy"] = localBypass
	args := launch.Args
	if name == "codex" {
		args = protectedCodexArgs(endpoint+"/route/"+protectedRoute.ID+"/v1", childArgs, os.Getenv("OPENAI_API_KEY") != "")
	} else {
		launch.Environment["ANTHROPIC_BASE_URL"] = endpoint + "/route/" + protectedRoute.ID
		launch.Environment["ANTHROPIC_API_KEY"] = veilproxy.EncodeCapability(created.Session.ID, routeToken)
	}
	childContext, cancelChild := context.WithCancel(ctx)
	leaseResult := make(chan error, 1)
	go maintainIntegrationLease(childContext, cancelChild, endpoint, adminToken, manifest.Agent.ID, registered.Generation, protectedLaunchHeartbeat, protectedLaunchLease, leaseResult)
	command := exec.CommandContext(childContext, launch.Executable, args...)
	configureProtectedCommand(command)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = protectedChildEnvironment(os.Environ(), launch.Environment)
	if err := command.Start(); err != nil {
		cancelChild()
		<-leaseResult
		return err
	}
	processDone := make(chan struct{})
	egressBinding := protectedEgressBinding{SessionID: created.Session.ID, AgentID: manifest.Agent.ID, Generation: registered.Generation, RouteID: protectedRoute.ID, AdminToken: adminToken}
	egressResult, err := startProtectedEgressWatch(childContext, cancelChild, processDone, command.Process.Pid, endpoint, egressBinding)
	if err != nil {
		cancelChild()
		_ = command.Wait()
		<-leaseResult
		return fmt.Errorf("start process egress observation: %w", err)
	}
	runErr := command.Wait()
	// A CLI can leave background descendants behind after its root exits. On
	// Unix the protected command's Cancel kills the entire process group even
	// after Wait has reaped the leader; other platforms safely return
	// os.ErrProcessDone. Complete this cleanup before telling the observer that
	// a root-disappearance error is an expected shutdown race.
	if command.Cancel != nil {
		_ = command.Cancel()
	}
	close(processDone)
	cancelChild()
	leaseErr := <-leaseResult
	egressErr := <-egressResult
	if leaseErr != nil {
		return leaseErr
	}
	if egressErr != nil {
		return egressErr
	}
	return runErr
}

func runNestedProtected(ctx context.Context, name string, childArgs []string) (resultErr error) {
	if name != "codex" && name != "claude" {
		return fmt.Errorf("nested protected launch for %s is not verified", name)
	}
	endpoint := os.Getenv("VEIL_CORE_ENDPOINT")
	parentSessionID := os.Getenv("VEIL_SESSION_ID")
	routeID := os.Getenv("VEIL_ROUTE_ID")
	parentRouteToken := os.Getenv("VEIL_PROTECTION_TOKEN")
	parentClient, err := nativesdk.NewRouteClient(endpoint, parentSessionID, routeID, parentRouteToken, nil)
	if err != nil {
		return fmt.Errorf("load parent route capability: %w", err)
	}
	manifest, err := discovery.Default().Inspect(ctx, name)
	if err != nil {
		return err
	}
	child, err := parentClient.CreateChild(ctx, nestedSessionMaxTTL)
	if err != nil {
		return fmt.Errorf("create nested protection session: %w", err)
	}
	if len(child.Routes) != 1 || child.Routes[0].RouteID != routeID || child.Routes[0].Token == "" {
		return errors.New("Core returned an incomplete nested route capability")
	}
	childRoute := child.Routes[0]
	childClient, err := nativesdk.NewRouteClient(endpoint, child.Session.ID, childRoute.RouteID, childRoute.Token, nil)
	if err != nil {
		return err
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if cleanupErr := childClient.Delete(cleanupContext); cleanupErr != nil && resultErr == nil && ctx.Err() == nil {
			resultErr = fmt.Errorf("revoke nested protection session: %w", cleanupErr)
		}
	}()
	launch, args, err := prepareNestedLaunch(name, manifest.Agent, endpoint, parentSessionID, routeID, child, childArgs, os.Getenv("OPENAI_API_KEY") != "")
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := launch.Cleanup(); cleanupErr != nil && resultErr == nil {
			resultErr = cleanupErr
		}
	}()
	launch.Environment["VEIL_ROUTE_ID"] = routeID
	localBypass := localNoProxy(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
	launch.Environment["NO_PROXY"] = localBypass
	launch.Environment["no_proxy"] = localBypass
	if _, err := fmt.Fprintf(os.Stderr, "AgentVeil nested protection: %s · %s · %s · non-interactive\n", name, child.Protocol, strings.Join(child.CapabilityTransports, "+")); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, launch.Executable, args...)
	configureProtectedCommand(command)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = protectedChildEnvironment(os.Environ(), launch.Environment)
	if err := command.Start(); err != nil {
		return err
	}
	runErr := command.Wait()
	if command.Cancel != nil {
		_ = command.Cancel()
	}
	return runErr
}

func prepareNestedLaunch(name string, agent domain.AgentInstance, endpoint, parentSessionID, routeID string, child nativesdk.ChildSession, childArgs []string, hasOpenAIKey bool) (integration.LaunchPlan, []string, error) {
	if len(child.Routes) != 1 || child.Routes[0].RouteID != routeID || child.Routes[0].Token == "" {
		return integration.LaunchPlan{}, nil, errors.New("Core returned an incomplete nested route capability")
	}
	childRoute := child.Routes[0]
	launch, err := integration.PrepareLaunch(agent, childArgs, endpoint, child.Session.ID, parentSessionID, childRoute.Token)
	if err != nil {
		return integration.LaunchPlan{}, nil, err
	}
	launch.Environment["VEIL_ROUTE_ID"] = routeID
	args := launch.Args
	switch name {
	case "codex":
		if child.Protocol != domain.ProtocolOpenAIResponses {
			return integration.LaunchPlan{}, nil, fmt.Errorf("nested Codex requires an OpenAI Responses Route, got %s", child.Protocol)
		}
		if !slices.Contains(child.CapabilityTransports, nativesdk.CapabilityTransportHeaders) {
			return integration.LaunchPlan{}, nil, fmt.Errorf("nested Codex cannot use Route capability transports %q", child.CapabilityTransports)
		}
		baseURL := endpoint + "/route/" + routeID + "/v1"
		args = protectedCodexArgs(baseURL, childArgs, hasOpenAIKey)
	case "claude":
		if child.Protocol != domain.ProtocolAnthropic || !slices.Contains(child.CapabilityTransports, nativesdk.CapabilityTransportAnthropicAPIKey) {
			return integration.LaunchPlan{}, nil, fmt.Errorf("nested Claude requires an Anthropic API-key capability Route, got %s/%q", child.Protocol, child.CapabilityTransports)
		}
		launch.Environment["ANTHROPIC_BASE_URL"] = endpoint + "/route/" + routeID
		launch.Environment["ANTHROPIC_API_KEY"] = veilproxy.EncodeCapability(child.Session.ID, childRoute.Token)
	default:
		return integration.LaunchPlan{}, nil, fmt.Errorf("nested protected launch for %s is not verified", name)
	}
	return launch, args, nil
}

func writeLaunchProtectionPlan(writer io.Writer, entry registry.Entry) error {
	if writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "display protection plan", "writer is required")
	}
	surfaces := make(map[string]domain.EgressSurface, len(entry.Manifest.Surfaces))
	for _, surface := range entry.Manifest.Surfaces {
		surfaces[surface.ID] = surface
	}
	summary := entry.Plan.Summary
	if _, err := fmt.Fprintf(writer, "AgentVeil protection plan: %s %s — %d protected, %d local, %d partial, %d observed, %d unprotected\n", entry.Manifest.Agent.Kind, entry.Manifest.Agent.Version, summary.Protected, summary.Local, summary.Partial, summary.Observed, summary.Unprotected); err != nil {
		return err
	}
	for _, coverage := range entry.Plan.Coverage {
		surface, ok := surfaces[coverage.SurfaceID]
		if !ok {
			return domain.NewError(domain.ErrInvalidContract, "display protection plan", "coverage references an unknown surface")
		}
		if _, err := fmt.Fprintf(writer, "  [%s] %s (%s) — %s\n", coverage.Status, surface.Name, surface.Protocol, coverage.Reason); err != nil {
			return err
		}
	}
	return nil
}

func validateHermesProtectedArgs(args []string) error {
	for _, argument := range args {
		normalized := strings.ToLower(strings.TrimSpace(argument))
		if normalized == "--ignore-user-config" || normalized == "--safe-mode" || normalized == "--profile" || normalized == "-p" || strings.HasPrefix(normalized, "--profile=") {
			return domain.NewError(domain.ErrPolicyBlocked, "prepare hermes launch", "launch argument can bypass the protected configuration")
		}
	}
	return nil
}

func hermesManifestConfigPath(manifest domain.AgentManifest) (string, error) {
	var path string
	for _, surface := range manifest.Surfaces {
		if surface.ConfigSource == "" || !filepath.IsAbs(surface.ConfigSource) || strings.ContainsRune(surface.ConfigSource, 0) {
			return "", errors.New("Hermes manifest contains an invalid configuration source")
		}
		if path == "" {
			path = surface.ConfigSource
		} else if path != surface.ConfigSource {
			return "", errors.New("Hermes manifest contains ambiguous configuration sources")
		}
	}
	if path == "" || filepath.Base(path) != "config.yaml" {
		return "", errors.New("Hermes manifest does not identify config.yaml")
	}
	return path, nil
}

func readProtectedHermesConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxHermesLaunchConfigBytes {
		return nil, errors.New("Hermes configuration type or size is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Hermes configuration could not be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return nil, errors.New("Hermes configuration changed before protected launch")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxHermesLaunchConfigBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxHermesLaunchConfigBytes {
		return nil, errors.New("Hermes configuration could not be read safely")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(content)) || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("Hermes configuration changed while protected launch was prepared")
	}
	return content, nil
}

func maintainIntegrationLease(ctx context.Context, cancel context.CancelFunc, endpoint, adminToken, agentID string, generation uint64, interval, leaseTTL time.Duration, result chan<- error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			result <- nil
			return
		case <-ticker.C:
			input := map[string]any{"generation": generation, "ttl_seconds": int64(leaseTTL / time.Second)}
			if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/agents/"+agentID+"/heartbeat", adminToken, input, nil); err != nil {
				cancel()
				result <- fmt.Errorf("protected integration lease failed: %w", err)
				return
			}
		}
	}
}

func fullyProtectedRoutes(entry registry.Entry) ([]domain.ProtectedRoute, error) {
	summary := entry.Plan.Summary
	if entry.State != registry.StateActive || summary.Total == 0 || summary.Partial != 0 || summary.Observed != 0 || summary.Unprotected != 0 || summary.Protected+summary.Local != summary.Total || len(entry.Plan.Routes) != summary.Protected || len(entry.Plan.Routes) == 0 {
		return nil, errors.New("agent does not have a fully protected route set")
	}
	seen := make(map[string]struct{}, len(entry.Plan.Routes))
	routes := append([]domain.ProtectedRoute(nil), entry.Plan.Routes...)
	for _, route := range routes {
		if route.ID == "" || route.SurfaceID == "" {
			return nil, errors.New("protected route set contains an incomplete route")
		}
		if _, duplicate := seen[route.ID]; duplicate {
			return nil, errors.New("protected route set contains duplicate route ids")
		}
		seen[route.ID] = struct{}{}
	}
	return routes, nil
}

func bindRouteCredentials(routes []domain.ProtectedRoute, created session.Created) (map[string]string, error) {
	if len(routes) == 0 || len(created.Routes) != len(routes) || len(created.Session.RouteIDs) != len(routes) {
		return nil, errors.New("Core returned an incomplete route credential set")
	}
	expected := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.ID == "" {
			return nil, errors.New("protected route id is empty")
		}
		if _, duplicate := expected[route.ID]; duplicate {
			return nil, errors.New("protected route id is duplicated")
		}
		expected[route.ID] = struct{}{}
	}
	credentials := make(map[string]string, len(routes))
	for _, credential := range created.Routes {
		if _, ok := expected[credential.RouteID]; !ok || credential.Token == "" {
			return nil, errors.New("Core returned an unknown or empty route credential")
		}
		if _, duplicate := credentials[credential.RouteID]; duplicate {
			return nil, errors.New("Core returned duplicate route credentials")
		}
		credentials[credential.RouteID] = credential.Token
	}
	sessionRoutes := make(map[string]struct{}, len(created.Session.RouteIDs))
	for _, routeID := range created.Session.RouteIDs {
		if _, ok := expected[routeID]; !ok {
			return nil, errors.New("Core session contains an unknown route")
		}
		if _, duplicate := sessionRoutes[routeID]; duplicate {
			return nil, errors.New("Core session contains a duplicate route")
		}
		sessionRoutes[routeID] = struct{}{}
	}
	return credentials, nil
}

func overlayEnvironment(base []string, overrides map[string]string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	replacedKeys := make(map[string]struct{}, len(overrides))
	for key := range overrides {
		replacedKeys[strings.ToLower(key)] = struct{}{}
	}
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, replaced := replacedKeys[strings.ToLower(key)]; replaced {
				continue
			}
		}
		result = append(result, entry)
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func protectedChildEnvironment(base []string, overrides map[string]string) []string {
	filteredBase := make([]string, 0, len(base))
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if found && isVeilChildControlVariable(key) {
			continue
		}
		filteredBase = append(filteredBase, entry)
	}
	filteredOverrides := make(map[string]string, len(overrides))
	for key, value := range overrides {
		if strings.EqualFold(key, "VEIL_ADMIN_TOKEN") {
			continue
		}
		filteredOverrides[key] = value
	}
	return overlayEnvironment(filteredBase, filteredOverrides)
}

func isVeilChildControlVariable(key string) bool {
	for _, protected := range []string{"VEIL_ADMIN_TOKEN", "VEIL_SESSION_ID", "VEIL_ROUTE_ID", "VEIL_PROTECTION_TOKEN", "VEIL_CORE_ENDPOINT", "VEIL_PARENT_SESSION"} {
		if strings.EqualFold(key, protected) {
			return true
		}
	}
	return false
}

func localNoProxy(values ...string) string {
	ordered := make([]string, 0)
	seen := map[string]struct{}{}
	for _, value := range append(values, "127.0.0.1", "localhost", "::1") {
		for _, entry := range strings.Split(value, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			key := strings.ToLower(entry)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			ordered = append(ordered, entry)
		}
	}
	return strings.Join(ordered, ",")
}

func protectedCodexArgs(baseURL string, childArgs []string, hasAPIKey bool) []string {
	values := []string{`model_provider="agentveil"`, `model_providers.agentveil.name="AgentVeil"`, `model_providers.agentveil.base_url="` + baseURL + `"`, `model_providers.agentveil.wire_api="responses"`, `model_providers.agentveil.supports_websockets=false`, `model_providers.agentveil.env_http_headers={"X-Veil-Session"="VEIL_SESSION_ID","X-Veil-Route-Token"="VEIL_PROTECTION_TOKEN"}`}
	if hasAPIKey {
		values = append(values, `model_providers.agentveil.env_key="OPENAI_API_KEY"`)
	} else {
		values = append(values, `model_providers.agentveil.requires_openai_auth=true`)
	}
	result := make([]string, 0, len(values)*2+len(childArgs))
	for _, value := range values {
		result = append(result, "-c", value)
	}
	return append(result, childArgs...)
}

func managementJSON(ctx context.Context, method, target, token string, input, output any) error {
	return managementJSONWithTimeout(ctx, method, target, token, input, output, 10*time.Second)
}

func managementJSONWithTimeout(ctx context.Context, method, target, token string, input, output any, timeout time.Duration) error {
	if ctx == nil || timeout <= 0 {
		return domain.NewError(domain.ErrInvalidContract, "call management API", "context and positive timeout are required")
	}
	var body io.Reader
	if input != nil {
		payload, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set(core.APIVersionHeader, core.APIVersion)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := validateManagementAPIVersion(response); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return managementResponseError(response)
	}
	if output != nil {
		return decodeManagementResponse(response, output)
	}
	return nil
}

func requireCompatibleCore(ctx context.Context, endpoint, token string) error {
	var health map[string]string
	if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/health", token, nil, &health); err != nil {
		return err
	}
	if health["api_version"] != core.APIVersion {
		return fmt.Errorf("incompatible Core health API version: expected %s", core.APIVersion)
	}
	return nil
}

func decodeManagementResponse(response *http.Response, output any) error {
	if response == nil || response.Body == nil || output == nil {
		return errors.New("management response and destination are required")
	}
	payload, err := readManagementResponse(response, maxManagementResponseBytes)
	if err != nil {
		return err
	}
	return decodeManagementPayload(payload, output)
}

func decodeManagementPayload(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("management response contains trailing data")
	}
	return nil
}

func managementResponseError(response *http.Response) error {
	payload, err := readManagementResponse(response, maxManagementErrorBytes)
	if err != nil {
		return fmt.Errorf("core returned %s with an invalid error response", response.Status)
	}
	var envelope struct {
		Error string `json:"error"`
	}
	if decodeManagementPayload(payload, &envelope) != nil || !validManagementErrorCode(envelope.Error) {
		return fmt.Errorf("core returned %s with an invalid error response", response.Status)
	}
	return fmt.Errorf("core returned %s: %s", response.Status, envelope.Error)
}

func validManagementErrorCode(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func readManagementResponse(response *http.Response, limit int64) ([]byte, error) {
	if response == nil || response.Body == nil || limit <= 0 {
		return nil, errors.New("management response and positive size limit are required")
	}
	if err := validateManagementAPIVersion(response); err != nil {
		return nil, err
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !protocol.MediaTypeIs(contentTypes[0], "application/json") {
		return nil, errors.New("management response requires one valid application/json content type")
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return nil, errors.New("management response content encoding is unsupported or ambiguous")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("management response exceeds its size limit")
	}
	if err := jsonsafe.Validate(payload); err != nil {
		return nil, errors.New("management response contains invalid or ambiguous JSON")
	}
	return payload, nil
}

func validateManagementAPIVersion(response *http.Response) error {
	if response == nil {
		return errors.New("management response is required")
	}
	versions := response.Header.Values(core.APIVersionHeader)
	if len(versions) != 1 || versions[0] != core.APIVersion {
		return fmt.Errorf("incompatible Core management API version: expected %s", core.APIVersion)
	}
	return nil
}

func serve() error {
	token := os.Getenv("VEIL_ADMIN_TOKEN")
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	configDir = filepath.Join(configDir, "agentveil")
	coreLock, err := instance.Acquire(filepath.Join(configDir, "core.lock"))
	if err != nil {
		return err
	}
	defer coreLock.Close()
	manager := session.NewManager()
	server, err := core.New(manager, token)
	if err != nil {
		return fmt.Errorf("VEIL_ADMIN_TOKEN must be set to a random value of at least 32 characters: %w", err)
	}
	integrationRegistry := registry.New(runtimeOptions())
	server.WithRegistry(integrationRegistry)
	var managedMonitor *registry.Monitor
	if managedPath := os.Getenv("VEIL_MANAGED_MANIFEST_PATH"); managedPath != "" {
		managedMonitor, err = configureManagedManifestMonitor(context.Background(), integrationRegistry, managedPath)
		if err != nil {
			return fmt.Errorf("configure managed manifest: %w", err)
		}
	}
	policyPath := os.Getenv("VEIL_POLICY_PATH")
	if policyPath == "" {
		policyPath = filepath.Join(configDir, "policy.json")
	}
	policyStore, err := policy.NewStore(policyPath)
	if err != nil {
		return err
	}
	if err := server.WithPolicyStore(policyStore); err != nil {
		return err
	}
	if err := configureRuleStore(server, configDir, os.Getenv("VEIL_RULE_VERIFY_KEY"), os.Getenv("VEIL_RULE_STORE_PATH")); err != nil {
		return err
	}
	if err := configureModelStore(server, configDir, os.Getenv("VEIL_MODEL_VERIFY_KEY"), os.Getenv("VEIL_MODEL_STORE_PATH")); err != nil {
		return err
	}
	auditPath := os.Getenv("VEIL_AUDIT_PATH")
	if auditPath == "" {
		auditPath = filepath.Join(configDir, "audit.jsonl")
	}
	retention := 30 * 24 * time.Hour
	if configured := os.Getenv("VEIL_AUDIT_RETENTION"); configured != "" {
		retention, err = time.ParseDuration(configured)
		if err != nil || retention <= 0 {
			return errors.New("VEIL_AUDIT_RETENTION must be a positive duration")
		}
	}
	auditStore, err := audit.NewStore(auditPath, retention, nil)
	if err != nil {
		return err
	}
	server.WithAuditor(auditStore)
	feedbackPath := os.Getenv("VEIL_FEEDBACK_PATH")
	if feedbackPath == "" {
		feedbackPath = filepath.Join(configDir, "feedback.json")
	}
	feedbackStore, err := feedback.NewStore(feedbackPath)
	if err != nil {
		return err
	}
	if err := server.WithFeedbackStore(feedbackStore); err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	statePath := filepath.Join(configDir, "core.json")
	if err := instance.WriteState(statePath, instance.State{SchemaVersion: "v1", APIEndpoint: server.Endpoint(), ProcessID: os.Getpid(), StartedAt: time.Now().UTC()}); err != nil {
		_ = server.Close(context.Background())
		return err
	}
	defer instance.RemoveState(statePath)
	fmt.Println(server.Endpoint())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if managedMonitor != nil {
		go managedMonitor.Run(ctx)
	}
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Close(shutdown)
}

func configureManagedManifestMonitor(ctx context.Context, integrationRegistry *registry.Registry, path string) (*registry.Monitor, error) {
	if ctx == nil || integrationRegistry == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "configure managed manifest", "context and registry are required")
	}
	source, err := registry.NewFileSnapshotSource(path)
	if err != nil {
		return nil, err
	}
	_, manifest, err := source.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if manifest.Agent.Mode != domain.ModeManaged {
		return nil, domain.NewError(domain.ErrInvalidContract, "configure managed manifest", "manifest agent mode must be managed")
	}
	monitor, err := registry.NewMonitor(integrationRegistry, source, manifest.Agent.ID, managedManifestInterval)
	if err != nil {
		return nil, err
	}
	entry, changed, err := monitor.Check(ctx)
	if err != nil || !changed || entry.State != registry.StateActive {
		if err != nil {
			return nil, err
		}
		return nil, domain.NewError(domain.ErrPolicyBlocked, "configure managed manifest", "initial managed protection plan is not active")
	}
	return monitor, nil
}

func configureRuleStore(server *core.Server, configDir, encodedKey, configuredPath string) error {
	if encodedKey == "" && configuredPath == "" {
		return nil
	}
	if server == nil || encodedKey == "" {
		return errors.New("VEIL_RULE_VERIFY_KEY is required when rule storage is configured")
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encodedKey {
		return errors.New("VEIL_RULE_VERIFY_KEY must be a canonical base64 Ed25519 public key")
	}
	path := configuredPath
	if path == "" {
		path = filepath.Join(configDir, "rules")
	}
	store, err := rulestore.New(path, ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	return server.WithRuleStore(store)
}

func configureModelStore(server *core.Server, configDir, encodedKey, configuredPath string) error {
	if encodedKey == "" && configuredPath == "" {
		return nil
	}
	if server == nil || encodedKey == "" {
		return errors.New("VEIL_MODEL_VERIFY_KEY is required when model storage is configured")
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encodedKey {
		return errors.New("VEIL_MODEL_VERIFY_KEY must be a canonical base64 Ed25519 public key")
	}
	path := configuredPath
	if path == "" {
		path = filepath.Join(configDir, "models")
	}
	store, err := modelstore.New(path, ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	return server.WithModelStore(store)
}

func runtimeOptions() planner.Options {
	capabilities := map[domain.Protocol]planner.Capability{}
	for _, protocol := range []domain.Protocol{domain.ProtocolOpenAIChat, domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic, domain.ProtocolGemini, domain.ProtocolMCPHTTP, domain.ProtocolMCPStreamable} {
		capabilities[protocol] = planner.Capability{Protocol: protocol, RequestInspection: true, ResponseInspection: true, StreamInspection: true, Observable: true}
	}
	return planner.Options{Capabilities: capabilities, DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}}
}

func writeInspection(writer io.Writer, manifest domain.AgentManifest) error {
	plan, err := planner.Build(manifest, runtimeOptions())
	if err != nil {
		return err
	}
	result := struct {
		Manifest      domain.AgentManifest   `json:"manifest"`
		Plan          domain.ProtectionPlan  `json:"protection_plan"`
		Compatibility []compatibility.Record `json:"compatibility"`
	}{manifest, plan, compatibility.ForAgent(manifest.Agent.Kind, manifest.Agent.Version, runtime.GOOS)}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func status() error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	token := os.Getenv("VEIL_ADMIN_TOKEN")
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	request, _ := http.NewRequest(http.MethodGet, endpoint+"/v1/health", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set(core.APIVersionHeader, core.APIVersion)
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := validateManagementAPIVersion(response); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("core returned %s", response.Status)
	}
	var health map[string]string
	if err := decodeManagementResponse(response, &health); err != nil {
		return err
	}
	fmt.Printf("AgentVeil Core: %s (API %s)\n", health["status"], health["api_version"])
	return nil
}

func compatibilityReport() error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	return writeCompatibilityReport(os.Stdout, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"))
}

func writeCompatibilityReport(writer io.Writer, endpoint, token string) error {
	if writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "write compatibility report", "writer is required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	var records []compatibility.Record
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/compatibility", token, nil, &records); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(records)
}

func writeOfflineCompatibilityReport(writer io.Writer) error {
	if writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "write offline compatibility report", "writer is required")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(compatibility.Current())
}

func diagnostics() error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, endpoint+"/v1/diagnostics", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+os.Getenv("VEIL_ADMIN_TOKEN"))
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set(core.APIVersionHeader, core.APIVersion)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := validateManagementAPIVersion(response); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("core returned %s", response.Status)
	}
	const maxDiagnosticBytes = 4 << 20
	payload, err := readManagementResponse(response, maxDiagnosticBytes)
	if err != nil {
		return fmt.Errorf("invalid diagnostic export: %w", err)
	}
	_, err = os.Stdout.Write(payload)
	return err
}

func rulesCommand(args []string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return executeRulesCommand(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), args)
}

func modelsCommand(args []string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), modelManagementTimeout)
	defer cancel()
	return executeModelsCommand(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), args)
}

func policyCommand(args []string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return executePolicyCommand(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), args)
}

func approvalsCommand(args []string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return executeApprovalsCommand(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), args)
}

func executeApprovalsCommand(ctx context.Context, writer io.Writer, endpoint, token string, args []string) error {
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "run approvals command", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	usage := errors.New("usage: veil approvals <list|resolve ID allow|redact|block>")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return usage
		}
		var approvals []policy.Approval
		if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/approvals", token, nil, &approvals); err != nil {
			return err
		}
		for _, approval := range approvals {
			if !validApprovalID(approval.ID) || approval.Finding.Validate(approval.Finding.Location.End) != nil {
				return errors.New("Core returned an invalid approval")
			}
		}
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(approvals)
	case "resolve":
		if len(args) != 3 || !validApprovalID(args[1]) {
			return usage
		}
		action := domain.Action(args[2])
		if action != domain.ActionAllow && action != domain.ActionRedact && action != domain.ActionBlock {
			return usage
		}
		return managementJSON(ctx, http.MethodPost, endpoint+"/v1/approvals/"+args[1], token, map[string]domain.Action{"action": action}, nil)
	default:
		return usage
	}
}

func validApprovalID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func executePolicyCommand(ctx context.Context, writer io.Writer, endpoint, token string, args []string) error {
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "run policy command", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	usage := errors.New("usage: veil policy <get|apply FILE>")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "get":
		if len(args) != 1 {
			return usage
		}
		var document policy.Document
		if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/policy", token, nil, &document); err != nil {
			return err
		}
		if _, err := document.Engine(); err != nil {
			return errors.New("Core returned an invalid policy document")
		}
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(document)
	case "apply":
		if len(args) != 2 {
			return usage
		}
		payload, err := readCLIFile(args[1], maxPolicyDocumentBytes)
		if err != nil {
			return fmt.Errorf("read policy document: %w", err)
		}
		var document policy.Document
		if err := decodeStrictJSON(payload, &document); err != nil {
			return fmt.Errorf("decode policy document: %w", err)
		}
		if _, err := document.Engine(); err != nil {
			return fmt.Errorf("validate policy document: %w", err)
		}
		return managementJSON(ctx, http.MethodPut, endpoint+"/v1/policy", token, document, nil)
	default:
		return usage
	}
}

func executeModelsCommand(ctx context.Context, writer io.Writer, endpoint, token string, args []string) error {
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "run models command", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	usage := errors.New("usage: veil models <list|install MANIFEST ARTIFACT|activate VERSION|deactivate|remove VERSION>")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return usage
		}
		var inventory struct {
			Active   string                `json:"active,omitempty"`
			Versions []modelstore.Manifest `json:"versions"`
			Runtime  struct {
				Connected     bool                            `json:"connected"`
				Required      bool                            `json:"required"`
				Active        bool                            `json:"active"`
				ArtifactBytes int64                           `json:"artifact_bytes,omitempty"`
				ResourceState string                          `json:"resource_state"`
				Resources     *detector.SemanticResourceUsage `json:"resources,omitempty"`
			} `json:"runtime"`
		}
		if err := managementJSONWithTimeout(ctx, http.MethodGet, endpoint+"/v1/models", token, nil, &inventory, modelManagementTimeout); err != nil {
			return err
		}
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inventory)
	case "install":
		if len(args) != 3 {
			return usage
		}
		manifestPayload, err := readCLIFile(args[1], maxModelManifestPayloadBytes)
		if err != nil {
			return fmt.Errorf("read model manifest: %w", err)
		}
		var manifest modelstore.Manifest
		if err := decodeStrictJSON(manifestPayload, &manifest); err != nil {
			return fmt.Errorf("decode model manifest: %w", err)
		}
		artifact, artifactInfo, err := openCLIFile(args[2], modelstore.MaxArtifactBytes)
		if err != nil {
			return fmt.Errorf("open model artifact: %w", err)
		}
		defer artifact.Close()
		if manifest.Size != artifactInfo.Size() {
			return errors.New("model artifact size does not match its signed manifest")
		}
		return uploadModel(ctx, endpoint, token, manifestPayload, manifest, artifact)
	case "activate":
		if len(args) != 2 {
			return usage
		}
		return managementJSONWithTimeout(ctx, http.MethodPut, endpoint+"/v1/models/active", token, map[string]string{"version": args[1]}, nil, modelManagementTimeout)
	case "deactivate":
		if len(args) != 1 {
			return usage
		}
		return managementJSONWithTimeout(ctx, http.MethodDelete, endpoint+"/v1/models/active", token, nil, nil, modelManagementTimeout)
	case "remove":
		if len(args) != 2 {
			return usage
		}
		return managementJSONWithTimeout(ctx, http.MethodDelete, endpoint+"/v1/models/"+url.PathEscape(args[1]), token, nil, nil, modelManagementTimeout)
	default:
		return usage
	}
}

func uploadModel(ctx context.Context, endpoint, token string, manifestPayload []byte, manifest modelstore.Manifest, artifact *os.File) error {
	if ctx == nil || artifact == nil {
		return domain.NewError(domain.ErrInvalidContract, "upload model", "context and artifact are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/models", artifact)
	if err != nil {
		return err
	}
	request.ContentLength = manifest.Size
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(core.APIVersionHeader, core.APIVersion)
	request.Header.Set(core.ModelManifestHeader, base64.StdEncoding.EncodeToString(manifestPayload))
	client := &http.Client{
		Timeout:       modelManagementTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if err := validateManagementAPIVersion(response); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return managementResponseError(response)
	}
	var installed modelstore.Manifest
	if err := decodeManagementResponse(response, &installed); err != nil {
		return err
	}
	if installed != manifest {
		return errors.New("Core returned a different installed model manifest")
	}
	return nil
}

func executeRulesCommand(ctx context.Context, writer io.Writer, endpoint, token string, args []string) error {
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "run rules command", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	usage := errors.New("usage: veil rules <list|install MANIFEST ARTIFACT|activate VERSION|deactivate|remove VERSION>")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return usage
		}
		var inventory struct {
			Active   string               `json:"active,omitempty"`
			Versions []rulestore.Manifest `json:"versions"`
		}
		if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/rules", token, nil, &inventory); err != nil {
			return err
		}
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inventory)
	case "install":
		if len(args) != 3 {
			return usage
		}
		manifestPayload, err := readCLIFile(args[1], 16<<10)
		if err != nil {
			return fmt.Errorf("read rule manifest: %w", err)
		}
		var manifest rulestore.Manifest
		if err := decodeStrictJSON(manifestPayload, &manifest); err != nil {
			return fmt.Errorf("decode rule manifest: %w", err)
		}
		artifact, err := readCLIFile(args[2], rulestore.MaxArtifactBytes)
		if err != nil {
			return fmt.Errorf("read rule artifact: %w", err)
		}
		if manifest.Size != int64(len(artifact)) {
			return errors.New("rule artifact size does not match its signed manifest")
		}
		request := struct {
			Manifest       rulestore.Manifest `json:"manifest"`
			ArtifactBase64 string             `json:"artifact_base64"`
		}{Manifest: manifest, ArtifactBase64: base64.StdEncoding.EncodeToString(artifact)}
		return managementJSON(ctx, http.MethodPost, endpoint+"/v1/rules", token, request, nil)
	case "activate":
		if len(args) != 2 {
			return usage
		}
		return managementJSON(ctx, http.MethodPut, endpoint+"/v1/rules/active", token, map[string]string{"version": args[1]}, nil)
	case "deactivate":
		if len(args) != 1 {
			return usage
		}
		return managementJSON(ctx, http.MethodDelete, endpoint+"/v1/rules/active", token, nil, nil)
	case "remove":
		if len(args) != 2 {
			return usage
		}
		return managementJSON(ctx, http.MethodDelete, endpoint+"/v1/rules/"+url.PathEscape(args[1]), token, nil, nil)
	default:
		return usage
	}
}

func readCLIFile(path string, maximum int64) ([]byte, error) {
	file, _, err := openCLIFile(path, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, domain.NewError(domain.ErrInvalidContract, "read CLI file", "file is empty or oversized")
	}
	return payload, nil
}

func openCLIFile(path string, maximum int64) (*os.File, os.FileInfo, error) {
	if path == "" || maximum <= 0 {
		return nil, nil, domain.NewError(domain.ErrInvalidContract, "open CLI file", "path and size limit are required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, nil, domain.NewError(domain.ErrInvalidContract, "open CLI file", "file type or size is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, domain.NewError(domain.ErrInvalidContract, "open CLI file", "file changed during validation")
	}
	return file, opened, nil
}

func decodeStrictJSON(payload []byte, output any) error {
	if output == nil || jsonsafe.Validate(payload) != nil {
		return domain.NewError(domain.ErrInvalidContract, "decode CLI JSON", "JSON is invalid or ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return domain.NewError(domain.ErrInvalidContract, "decode CLI JSON", "JSON does not match its schema")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.NewError(domain.ErrInvalidContract, "decode CLI JSON", "JSON contains trailing data")
	}
	return nil
}

func resolveCoreEndpoint(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	state, err := instance.LoadState(filepath.Join(configDir, "agentveil", "core.json"))
	if err != nil {
		return "", errors.New("AgentVeil Core endpoint is unavailable; start 'veil serve' or set VEIL_CORE_ENDPOINT")
	}
	return state.APIEndpoint, nil
}
