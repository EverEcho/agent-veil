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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	veilproxy "github.com/agentveil/agentveil/internal/proxy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
)

const protectedLaunchLease = 30 * time.Second
const protectedLaunchHeartbeat = 10 * time.Second

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
		return errors.New("usage: veil <diagnostics|discover|inspect|run|serve|status>")
	}
	switch args[0] {
	case "serve":
		return serve()
	case "status":
		return status()
	case "diagnostics":
		if len(args) != 1 {
			return errors.New("usage: veil diagnostics")
		}
		return diagnostics()
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
		if len(args) < 2 {
			return errors.New("usage: veil run <codex|claude> [-- agent arguments]")
		}
		childArgs := args[2:]
		if len(childArgs) > 0 && childArgs[0] == "--" {
			childArgs = childArgs[1:]
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runProtected(ctx, args[1], childArgs)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runProtected(ctx context.Context, name string, childArgs []string) (resultErr error) {
	if name != "codex" && name != "claude" {
		return fmt.Errorf("protected launch for %s is not verified", name)
	}
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	adminToken := os.Getenv("VEIL_ADMIN_TOKEN")
	if _, err := core.ListenAddress(endpoint); err != nil {
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
	if len(protectedRoutes) != 1 {
		return errors.New("agent-specific multi-route launch injection is not verified")
	}
	protectedRoute := protectedRoutes[0]
	routeIDs := []string{protectedRoute.ID}
	var created session.Created
	if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/sessions", adminToken, map[string]any{"route_ids": routeIDs, "ttl_seconds": 86400}, &created); err != nil {
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
	launch, err := integration.PrepareLaunch(manifest.Agent, childArgs, endpoint, created.Session.ID, "", routeToken)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := launch.Cleanup(); cleanupErr != nil && resultErr == nil {
			resultErr = cleanupErr
		}
	}()
	localBypass := localNoProxy(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
	launch.Environment["NO_PROXY"] = localBypass
	launch.Environment["no_proxy"] = localBypass
	args := childArgs
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
	command.Env = overlayEnvironment(os.Environ(), launch.Environment)
	if err := command.Start(); err != nil {
		cancelChild()
		<-leaseResult
		return err
	}
	egressBinding := protectedEgressBinding{SessionID: created.Session.ID, AgentID: manifest.Agent.ID, Generation: registered.Generation, RouteID: protectedRoute.ID, AdminToken: adminToken}
	egressResult, err := startProtectedEgressWatch(childContext, cancelChild, command.Process.Pid, endpoint, egressBinding)
	if err != nil {
		cancelChild()
		_ = command.Wait()
		<-leaseResult
		return fmt.Errorf("start process egress observation: %w", err)
	}
	runErr := command.Wait()
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
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; found && replaced {
			continue
		}
		result = append(result, entry)
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
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
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("core returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if output != nil {
		return json.NewDecoder(response.Body).Decode(output)
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
	server.WithRegistry(registry.New(runtimeOptions()))
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
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Close(shutdown)
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
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("core returned %s", response.Status)
	}
	var health map[string]string
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
		return err
	}
	fmt.Printf("AgentVeil Core: %s (API %s)\n", health["status"], health["api_version"])
	return nil
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
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("core returned %s", response.Status)
	}
	const maxDiagnosticBytes = 4 << 20
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxDiagnosticBytes+1))
	if err != nil {
		return err
	}
	if len(payload) > maxDiagnosticBytes {
		return errors.New("diagnostic export exceeds its size limit")
	}
	_, err = os.Stdout.Write(payload)
	return err
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
