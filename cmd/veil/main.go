package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/discovery"
	"github.com/agentveil/agentveil/internal/domain"
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
		return errors.New("usage: veil <inspect|serve|status>")
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
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(manifest)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve() error {
	token := os.Getenv("VEIL_ADMIN_TOKEN")
	manager := session.NewManager()
	server, err := core.New(manager, token)
	if err != nil {
		return fmt.Errorf("VEIL_ADMIN_TOKEN must be set to a random value of at least 32 characters: %w", err)
	}
	capabilities := map[domain.Protocol]planner.Capability{}
	for _, protocol := range []domain.Protocol{domain.ProtocolOpenAIChat, domain.ProtocolOpenAIResponses, domain.ProtocolAnthropic, domain.ProtocolGemini, domain.ProtocolMCPHTTP} {
		capabilities[protocol] = planner.Capability{Protocol: protocol, RequestInspection: true, ResponseInspection: true, StreamInspection: true, Observable: true}
	}
	server.WithRegistry(registry.New(planner.Options{Capabilities: capabilities, DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}}))
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
