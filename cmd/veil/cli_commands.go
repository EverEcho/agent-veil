package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/audit"
	"github.com/agentveil/agentveil/internal/compatibility"
	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/planner"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/registry"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
)

func writeInspection(writer io.Writer, manifest domain.AgentManifest) error {
	if writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "write inspection", "writer is required")
	}
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
	return writeCoreStatus(os.Stdout, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"))
}

func writeCoreStatus(writer io.Writer, endpoint, token string) error {
	if writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "write Core status", "writer is required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	var health struct {
		Status        string `json:"status"`
		APIVersion    string `json:"api_version"`
		Audit         string `json:"audit"`
		AuditFailures string `json:"audit_failures,omitempty"`
		Semantic      string `json:"semantic"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/health", token, nil, &health); err != nil {
		return err
	}
	if (health.Status != "ok" && health.Status != "degraded") || health.APIVersion != core.APIVersion || (health.Audit != "disabled" && health.Audit != "ok" && health.Audit != "error") || (health.Semantic != "disabled" && health.Semantic != "ready" && health.Semantic != "active" && health.Semantic != "required_unavailable") {
		return errors.New("Core returned an invalid health state")
	}
	if health.Audit == "error" && health.AuditFailures == "" || health.Audit != "error" && health.AuditFailures != "" {
		return errors.New("Core returned inconsistent audit health")
	}
	if health.AuditFailures != "" {
		if failures, err := strconv.ParseUint(health.AuditFailures, 10, 64); err != nil || failures == 0 {
			return errors.New("Core returned an invalid audit failure count")
		}
	}
	_, err := fmt.Fprintf(writer, "AgentVeil Core: %s (API %s)\nAudit: %s", health.Status, health.APIVersion, health.Audit)
	if err != nil {
		return err
	}
	if health.AuditFailures != "" {
		if _, err := fmt.Fprintf(writer, " (%s failures)", health.AuditFailures); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(writer, "\nSemantic: %s\n", health.Semantic)
	return err
}

func compatibilityReport() error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	return writeCompatibilityReport(os.Stdout, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"))
}

func auditReport() error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	return writeAuditReport(os.Stdout, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"))
}

func writeAuditReport(writer io.Writer, endpoint, token string) error {
	if writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "write audit report", "writer is required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var events []domain.AuditEvent
	if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/audit", token, nil, &events); err != nil {
		return err
	}
	for _, event := range events {
		if _, err := audit.Marshal(event); err != nil {
			return errors.New("Core returned an invalid audit event")
		}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(events)
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
	response, err := managementHTTPClient(10 * time.Second).Do(request)
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

func liveStateCommand(resource string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return writeLiveState(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), resource)
}

func agentsCommand(args []string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return executeAgentsCommand(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), args)
}

func executeAgentsCommand(ctx context.Context, writer io.Writer, endpoint, token string, args []string) error {
	usage := errors.New("usage: veil agents <list|remove AGENT_ID --generation GENERATION>")
	if len(args) == 0 || len(args) == 1 && args[0] == "list" {
		return writeLiveState(ctx, writer, endpoint, token, "agents")
	}
	if len(args) != 4 || args[0] != "remove" || !validResourceID(args[1]) || args[2] != "--generation" {
		return usage
	}
	generation, err := strconv.ParseUint(args[3], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != args[3] {
		return usage
	}
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "remove agent registration", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	target := endpoint + "/v1/agents/" + url.PathEscape(args[1]) + "?generation=" + strconv.FormatUint(generation, 10)
	return managementJSON(ctx, http.MethodDelete, target, token, nil, nil)
}

func validResourceID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func sessionsCommand(args []string, writer io.Writer) error {
	endpoint, err := resolveCoreEndpoint(os.Getenv("VEIL_CORE_ENDPOINT"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return executeSessionsCommand(ctx, writer, endpoint, os.Getenv("VEIL_ADMIN_TOKEN"), args)
}

func executeSessionsCommand(ctx context.Context, writer io.Writer, endpoint, token string, args []string) error {
	usage := errors.New("usage: veil sessions <list|revoke SESSION_ID>")
	if len(args) == 0 || len(args) == 1 && args[0] == "list" {
		return writeLiveState(ctx, writer, endpoint, token, "sessions")
	}
	if len(args) != 2 || args[0] != "revoke" || !validSessionID(args[1]) {
		return usage
	}
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "revoke session", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	return managementJSON(ctx, http.MethodDelete, endpoint+"/v1/sessions/"+args[1], token, nil, nil)
}

func validSessionID(value string) bool {
	if !strings.HasPrefix(value, "session-") || len(value) != len("session-")+32 {
		return false
	}
	for _, character := range value[len("session-"):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func writeLiveState(ctx context.Context, writer io.Writer, endpoint, token, resource string) error {
	if ctx == nil || writer == nil {
		return domain.NewError(domain.ErrInvalidContract, "read live state", "context and writer are required")
	}
	if _, err := core.ListenAddress(endpoint); err != nil {
		return err
	}
	var output any
	switch resource {
	case "agents":
		var entries []registry.Entry
		if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/agents", token, nil, &entries); err != nil {
			return err
		}
		if len(entries) > 1024 {
			return errors.New("Core returned too many agent registrations")
		}
		output = entries
	case "sessions":
		var sessions []domain.ProtectionSession
		if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/sessions", token, nil, &sessions); err != nil {
			return err
		}
		if len(sessions) > session.MaximumSessions {
			return errors.New("Core returned too many sessions")
		}
		output = sessions
	case "calls":
		var tree map[string][]registry.CallNode
		if err := managementJSON(ctx, http.MethodGet, endpoint+"/v1/call-tree", token, nil, &tree); err != nil {
			return err
		}
		nodes := make([]registry.CallNode, 0)
		for parentID, children := range tree {
			for _, node := range children {
				if node.ParentSessionID != parentID {
					return errors.New("Core returned an invalid call tree")
				}
				nodes = append(nodes, node)
				if len(nodes) > session.MaximumSessions {
					return errors.New("Core returned too many call nodes")
				}
			}
		}
		if _, err := registry.CallTree(nodes); err != nil {
			return errors.New("Core returned an invalid call tree")
		}
		output = tree
	default:
		return errors.New("live state resource is invalid")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
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
	response, err := managementHTTPClient(modelManagementTimeout).Do(request)
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
