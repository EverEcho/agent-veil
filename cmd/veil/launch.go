package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/integration"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
	nativesdk "github.com/agentveil/agentveil/sdk/native"
)

type protectedEgressBinding struct {
	SessionID  string
	AgentID    string
	Generation uint64
	RouteID    string
	AdminToken string
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
		userConfigDir, configErr := os.UserConfigDir()
		if configErr != nil {
			return configErr
		}
		launchRoot := filepath.Join(userConfigDir, "agentveil", "launches")
		launch, err = integration.PrepareHermesLaunch(manifest.Agent, childArgs, endpoint, created.Session.ID, "", routeToken, filepath.Dir(configPath), launchRoot, rewritten, runtimeEnvironment)
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
