package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/debugtrace"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/feedback"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/integration"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
)

func serve() (resultErr error) {
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
	defer func() {
		if closeErr := coreLock.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release Core instance lock: %w", closeErr))
		}
	}()
	statePath := filepath.Join(configDir, "core.json")
	if err := instance.RemoveState(statePath); err != nil {
		return fmt.Errorf("remove stale Core state: %w", err)
	}
	if err := integration.ResetHermesLaunchRoot(filepath.Join(configDir, "launches")); err != nil {
		return fmt.Errorf("recover stale Hermes launch resources: %w", err)
	}
	if err := integration.ResetCodexDesktopLaunchRoot(filepath.Join(configDir, "codex-desktop-launches")); err != nil {
		return fmt.Errorf("recover stale Codex Desktop launch resources: %w", err)
	}
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
	debugTraceStore, err := debugtrace.NewStore(filepath.Join(configDir, "developer.json"), filepath.Join(configDir, "developer-traces.jsonl"), 24*time.Hour)
	if err != nil {
		return err
	}
	if err := server.WithDebugTraceStore(debugTraceStore); err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	if err := instance.WriteState(statePath, instance.State{SchemaVersion: "v1", APIEndpoint: server.Endpoint(), InstanceID: server.InstanceID(), ProcessID: os.Getpid(), StartedAt: time.Now().UTC()}); err != nil {
		_ = server.Close(context.Background())
		return err
	}
	defer func() {
		if removeErr := instance.RemoveState(statePath); removeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove Core state: %w", removeErr))
		}
	}()
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
	for _, protocolType := range protocol.ContentProtectedProtocols() {
		capabilities[protocolType] = planner.Capability{Protocol: protocolType, RequestInspection: true, ResponseInspection: true, StreamInspection: true, Observable: true}
	}
	return planner.Options{Capabilities: capabilities, DefaultPolicy: "default", Network: domain.NetworkRoute{Type: domain.NetworkDirect}}
}
