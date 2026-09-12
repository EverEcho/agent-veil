package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/session"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "veil:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: veil <inspect|run|serve|status>")
	}
	switch args[0] {
	case "serve":
		return serve()
	case "status":
		return status()
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: veil inspect <codex|claude|hermes|cursor>")
		}
		manifest, err := discovery.Default().Inspect(context.Background(), args[1])
		if err != nil {
			return err
		}
		return writeInspection(os.Stdout, manifest)
	case "run":
		if len(args) < 2 {
			return errors.New("usage: veil run codex [-- agent arguments]")
		}
		childArgs := args[2:]
		if len(childArgs) > 0 && childArgs[0] == "--" {
			childArgs = childArgs[1:]
		}
		return runProtected(context.Background(), args[1], childArgs)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runProtected(ctx context.Context, name string, childArgs []string) error {
	if name != "codex" {
		return fmt.Errorf("protected launch for %s is not verified", name)
	}
	endpoint, adminToken := os.Getenv("VEIL_CORE_ENDPOINT"), os.Getenv("VEIL_ADMIN_TOKEN")
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	manifest, err := discovery.Default().Inspect(ctx, name)
	if err != nil {
		return err
	}
	plan, err := planner.Build(manifest, runtimeOptions())
	if err != nil {
		return err
	}
	if len(plan.Routes) != 1 || plan.Summary.Protected != plan.Summary.Total {
		return errors.New("agent does not have exactly one fully protected route")
	}
	if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/agents", adminToken, manifest, nil); err != nil {
		return err
	}
	var created session.Created
	if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/sessions", adminToken, map[string]any{"route_ids": []string{plan.Routes[0].ID}, "ttl_seconds": 86400}, &created); err != nil {
		return err
	}
	defer func() {
		_ = managementJSON(context.Background(), http.MethodDelete, endpoint+"/v1/sessions/"+created.Session.ID, adminToken, nil, nil)
	}()
	launch, err := integration.PrepareLaunch(manifest.Agent, childArgs, endpoint, created.Session.ID, "", created.Routes[0].Token)
	if err != nil {
		return err
	}
	args := protectedCodexArgs(endpoint+"/route/"+plan.Routes[0].ID+"/v1", childArgs, os.Getenv("OPENAI_API_KEY") != "")
	command := exec.CommandContext(ctx, launch.Executable, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = append(os.Environ(), "VEIL_SESSION_ID="+created.Session.ID, "VEIL_PROTECTION_TOKEN="+created.Routes[0].Token, "VEIL_CORE_ENDPOINT="+endpoint)
	return command.Run()
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
	manager := session.NewManager()
	server, err := core.New(manager, token)
	if err != nil {
		return fmt.Errorf("VEIL_ADMIN_TOKEN must be set to a random value of at least 32 characters: %w", err)
	}
	server.WithRegistry(registry.New(runtimeOptions()))
	if err := server.Start(); err != nil {
		return err
	}
	fmt.Println(server.Endpoint())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Close(shutdown)
}

func runtimeOptions() planner.Options {
	capabilities := map[domain.Protocol]planner.Capability{}
	for _, protocol := range []domain.Protocol{domain.ProtocolOpenAIChat, domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic, domain.ProtocolGemini, domain.ProtocolMCPHTTP} {
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
		Manifest domain.AgentManifest  `json:"manifest"`
		Plan     domain.ProtectionPlan `json:"protection_plan"`
	}{manifest, plan}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func status() error {
	endpoint, token := os.Getenv("VEIL_CORE_ENDPOINT"), os.Getenv("VEIL_ADMIN_TOKEN")
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
