package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/rulestore"
	"github.com/agentveil/agentveil/internal/session"
)

type literalSemantic string

type resourceSemantic struct {
	literalSemantic
	usage detector.SemanticResourceUsage
	err   error
	panic bool
}

func (runtime resourceSemantic) SemanticResourceUsage() (detector.SemanticResourceUsage, error) {
	if runtime.panic {
		panic("runtime metrics failure")
	}
	return runtime.usage, runtime.err
}

func TestPolicyAPIAtomicallyUpdatesAndPersistsEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "policy.json")
	store, _ := policy.NewStore(path)
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithPolicyStore(store); err != nil {
		t.Fatal(err)
	}
	document := policy.Document{SchemaVersion: "v1", Default: domain.ActionRedact, Rules: []policy.Rule{{Scope: policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"}, Action: domain.ActionBlock}}}
	payload, _ := json.Marshal(document)
	request := httptest.NewRequest(http.MethodPut, "/v1/policy", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.updatePolicy)(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	decision, err := s.policyEngine().Decide(policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"}, true)
	if err != nil || decision.Action != domain.ActionBlock {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	restarted, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := restarted.WithPolicyStore(store); err != nil {
		t.Fatal(err)
	}
	decision, _ = restarted.policyEngine().Decide(policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"}, true)
	if decision.Action != domain.ActionBlock {
		t.Fatalf("persisted decision=%+v", decision)
	}
}

func TestDetectionTestAPIPreviewsMostSpecificPolicyWithoutEchoingInput(t *testing.T) {
	engine := policy.Engine{Default: domain.ActionAllow, Rules: []policy.Rule{{
		Scope:  policy.Scope{AgentID: "agent-a", Provider: "api.example", SurfaceID: "primary", FindingType: "pii.email"},
		Action: domain.ActionAsk,
	}}}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.WithPolicy(engine)
	request := httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"contact private@example.com","scope":{"agent_id":"agent-a","provider":"api.example","surface_id":"primary"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "private@example.com") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response detectionTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 {
		t.Fatalf("response=%+v", response)
	}
	decision := response.Results[0].Decision
	if decision.Action != domain.ActionAsk || decision.Source != "rule" || decision.Reason != "most specific matching rule" || decision.MatchedScope == nil || decision.MatchedScope.FindingType != "pii.email" {
		t.Fatalf("decision=%+v", decision)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"safe","scope":{"workspace":"/raw/path"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder = httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_DETECTION_SCOPE") {
		t.Fatalf("invalid scope status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRuleStoreActivePackConfiguresCoreDataPlane(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	sum := sha256.Sum256(payload)
	manifest := rulestore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
	if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/detect", strings.NewReader(`{"text":"reference TICKET-123456"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	recorder := httptest.NewRecorder()
	s.auth(s.testDetection)(recorder, request)
	var response detectionTestResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil || len(response.Results) != 1 || response.Results[0].Finding.Detector != "rule_pack" {
		t.Fatalf("status=%d response=%+v body=%s", recorder.Code, response, recorder.Body.String())
	}
}

func TestRulePackManagementHotSwapsAndDeactivatesScanner(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	sum := sha256.Sum256(payload)
	manifest := rulestore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
	if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	s.semantic = literalSemantic("Alice")
	s.semanticRequired = true
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}

	inventoryRecorder := httptest.NewRecorder()
	s.listRulePacks(inventoryRecorder, httptest.NewRequest(http.MethodGet, "/v1/rules", nil))
	var inventory rulePackInventory
	if inventoryRecorder.Code != http.StatusOK || json.Unmarshal(inventoryRecorder.Body.Bytes(), &inventory) != nil || inventory.Active != "" || len(inventory.Versions) != 1 {
		t.Fatalf("inventory status=%d value=%+v body=%s", inventoryRecorder.Code, inventory, inventoryRecorder.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPut, "/v1/rules/active", strings.NewReader(`{"version":"1.0.0"}`))
	activate.Header.Set("Content-Type", "application/json")
	activateRecorder := httptest.NewRecorder()
	s.activateRulePack(activateRecorder, activate)
	if activateRecorder.Code != http.StatusNoContent {
		t.Fatalf("activation status=%d body=%s", activateRecorder.Code, activateRecorder.Body.String())
	}
	findings, err := s.currentScanner().ScanChecked("/input", "reference TICKET-123456")
	if err != nil || len(findings) != 1 || findings[0].Finding.Detector != "rule_pack" {
		t.Fatalf("active findings=%+v error=%v", findings, err)
	}
	semanticFindings, err := s.currentScanner().ScanChecked("/input", "Alice")
	if err != nil || len(semanticFindings) != 1 || semanticFindings[0].Finding.Detector != "semantic" {
		t.Fatalf("rule activation lost semantic detector: findings=%+v error=%v", semanticFindings, err)
	}

	deactivateRecorder := httptest.NewRecorder()
	s.deactivateRulePack(deactivateRecorder, httptest.NewRequest(http.MethodDelete, "/v1/rules/active", nil))
	if deactivateRecorder.Code != http.StatusNoContent {
		t.Fatalf("deactivation status=%d body=%s", deactivateRecorder.Code, deactivateRecorder.Body.String())
	}
	findings, err = s.currentScanner().ScanChecked("/input", "reference TICKET-123456")
	if err != nil || len(findings) != 0 {
		t.Fatalf("built-in findings=%+v error=%v", findings, err)
	}
	semanticFindings, err = s.currentScanner().ScanChecked("/input", "Alice")
	if err != nil || len(semanticFindings) != 1 || semanticFindings[0].Finding.Detector != "semantic" {
		t.Fatalf("rule deactivation lost semantic detector: findings=%+v error=%v", semanticFindings, err)
	}
	if _, _, err := store.OpenActive(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rule store remained active: %v", err)
	}
}

func TestRulePackManagementRemovesOnlyInactiveVersions(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	for _, version := range []string{"1.0.0", "1.1.0"} {
		sum := sha256.Sum256(payload)
		manifest := rulestore.Manifest{SchemaVersion: "v1", Version: version, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
		manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
		if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Activate("1.1.0"); err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}

	activeRequest := httptest.NewRequest(http.MethodDelete, "/v1/rules/1.1.0", nil)
	activeRequest.SetPathValue("version", "1.1.0")
	activeRecorder := httptest.NewRecorder()
	s.removeRulePack(activeRecorder, activeRequest)
	if activeRecorder.Code != http.StatusConflict {
		t.Fatalf("active removal status=%d body=%s", activeRecorder.Code, activeRecorder.Body.String())
	}

	inactiveRequest := httptest.NewRequest(http.MethodDelete, "/v1/rules/1.0.0", nil)
	inactiveRequest.SetPathValue("version", "1.0.0")
	inactiveRecorder := httptest.NewRecorder()
	s.removeRulePack(inactiveRecorder, inactiveRequest)
	if inactiveRecorder.Code != http.StatusNoContent {
		t.Fatalf("inactive removal status=%d body=%s", inactiveRecorder.Code, inactiveRecorder.Body.String())
	}
	versions, err := store.List()
	if err != nil || len(versions) != 1 || versions[0].Version != "1.1.0" {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}
}

func TestRulePackManagementInstallsOnlyCanonicalSignedArtifacts(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := rulestore.New(filepath.Join(t.TempDir(), "rules"), public)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithRuleStore(store); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detector.RulePack{SchemaVersion: "v1", Rules: []detector.RuleDefinition{{ID: "custom.ticket", Category: "internal.ticket", Severity: domain.SeverityHigh, SuggestedAction: domain.ActionRedact, Pattern: `TICKET-[0-9]{6}`}}})
	sum := sha256.Sum256(payload)
	manifest := rulestore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, rulestore.SigningPayload(manifest)))
	requestPayload, _ := json.Marshal(rulePackInstall{Manifest: manifest, ArtifactBase64: base64.StdEncoding.EncodeToString(payload)})
	request := httptest.NewRequest(http.MethodPost, "/v1/rules", bytes.NewReader(requestPayload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.installRulePack(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("installation status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	versions, err := store.List()
	if err != nil || len(versions) != 1 || versions[0].Version != "1.0.0" {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}

	for name, mutate := range map[string]func(*rulePackInstall){
		"noncanonical base64": func(value *rulePackInstall) { value.ArtifactBase64 += "\n" },
		"bad signature": func(value *rulePackInstall) {
			value.Manifest.Version = "2.0.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := rulePackInstall{Manifest: manifest, ArtifactBase64: base64.StdEncoding.EncodeToString(payload)}
			mutate(&candidate)
			body, _ := json.Marshal(candidate)
			request := httptest.NewRequest(http.MethodPost, "/v1/rules", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			s.installRulePack(recorder, request)
			if recorder.Code == http.StatusCreated {
				t.Fatal("unsafe rule artifact was installed")
			}
		})
	}
}

func TestModelManagementStreamsSignedArtifactsAndManagesLifecycle(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := modelstore.New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithModelStore(store); err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified-onnx-model")
	sum := sha256.Sum256(payload)
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, modelstore.SigningPayload(manifest)))
	manifestJSON, _ := json.Marshal(manifest)
	upload := httptest.NewRequest(http.MethodPost, "/v1/models", bytes.NewReader(payload))
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set(ModelManifestHeader, base64.StdEncoding.EncodeToString(manifestJSON))
	uploadRecorder := httptest.NewRecorder()
	s.installModel(uploadRecorder, upload)
	if uploadRecorder.Code != http.StatusCreated {
		t.Fatalf("installation status=%d body=%s", uploadRecorder.Code, uploadRecorder.Body.String())
	}

	inventoryRecorder := httptest.NewRecorder()
	s.listModels(inventoryRecorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	var inventory modelInventory
	if inventoryRecorder.Code != http.StatusOK || json.Unmarshal(inventoryRecorder.Body.Bytes(), &inventory) != nil || inventory.Active != "" || len(inventory.Versions) != 1 || inventory.Versions[0].Version != manifest.Version {
		t.Fatalf("inventory status=%d value=%+v body=%s", inventoryRecorder.Code, inventory, inventoryRecorder.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPut, "/v1/models/active", strings.NewReader(`{"version":"1.0.0"}`))
	activate.Header.Set("Content-Type", "application/json")
	activateRecorder := httptest.NewRecorder()
	s.activateModel(activateRecorder, activate)
	if activateRecorder.Code != http.StatusNoContent {
		t.Fatalf("activation status=%d body=%s", activateRecorder.Code, activateRecorder.Body.String())
	}
	activeRemoval := httptest.NewRequest(http.MethodDelete, "/v1/models/1.0.0", nil)
	activeRemoval.SetPathValue("version", "1.0.0")
	activeRemovalRecorder := httptest.NewRecorder()
	s.removeModel(activeRemovalRecorder, activeRemoval)
	if activeRemovalRecorder.Code != http.StatusConflict {
		t.Fatalf("active removal status=%d body=%s", activeRemovalRecorder.Code, activeRemovalRecorder.Body.String())
	}

	deactivateRecorder := httptest.NewRecorder()
	s.deactivateModel(deactivateRecorder, httptest.NewRequest(http.MethodDelete, "/v1/models/active", nil))
	if deactivateRecorder.Code != http.StatusNoContent {
		t.Fatalf("deactivation status=%d body=%s", deactivateRecorder.Code, deactivateRecorder.Body.String())
	}
	remove := httptest.NewRequest(http.MethodDelete, "/v1/models/1.0.0", nil)
	remove.SetPathValue("version", "1.0.0")
	removeRecorder := httptest.NewRecorder()
	s.removeModel(removeRecorder, remove)
	if removeRecorder.Code != http.StatusNoContent {
		t.Fatalf("removal status=%d body=%s", removeRecorder.Code, removeRecorder.Body.String())
	}
	if versions, err := store.List(); err != nil || len(versions) != 0 {
		t.Fatalf("versions=%+v error=%v", versions, err)
	}
}

func TestModelUploadRequiresCanonicalBoundedRepresentation(t *testing.T) {
	manifest := modelstore.Manifest{SchemaVersion: "v1", Version: "1.0.0", Size: 4, SHA256: strings.Repeat("0", 64), Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	manifestJSON, _ := json.Marshal(manifest)
	encoded := base64.StdEncoding.EncodeToString(manifestJSON)
	for _, test := range []struct {
		name          string
		contentTypes  []string
		encodings     []string
		manifests     []string
		contentLength int64
	}{
		{name: "missing manifest", contentTypes: []string{"application/octet-stream"}, contentLength: 4},
		{name: "duplicate manifest", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded, encoded}, contentLength: 4},
		{name: "noncanonical manifest", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded + "\n"}, contentLength: 4},
		{name: "compressed", contentTypes: []string{"application/octet-stream"}, encodings: []string{"gzip"}, manifests: []string{encoded}, contentLength: 4},
		{name: "ambiguous content type", contentTypes: []string{"application/octet-stream", "application/octet-stream"}, manifests: []string{encoded}, contentLength: 4},
		{name: "unknown body length", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded}, contentLength: -1},
		{name: "wrong body length", contentTypes: []string{"application/octet-stream"}, manifests: []string{encoded}, contentLength: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/models", strings.NewReader("onnx"))
			request.Header["Content-Type"] = test.contentTypes
			request.Header["Content-Encoding"] = test.encodings
			request.Header[ModelManifestHeader] = test.manifests
			request.ContentLength = test.contentLength
			if _, err := decodeModelUpload(request); err == nil {
				t.Fatal("unsafe model upload representation was accepted")
			}
		})
	}
}

func TestSemanticRuntimeLoadsActiveModelAndPreservesScannerOnFailedSwitch(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := modelstore.New(filepath.Join(t.TempDir(), "models"), public)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.0.0", "2.0.0"} {
		payload := []byte("onnx-" + version)
		sum := sha256.Sum256(payload)
		manifest := modelstore.Manifest{SchemaVersion: "v1", Version: version, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
		manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, modelstore.SigningPayload(manifest)))
		if err := store.Install(manifest, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Activate("1.0.0"); err != nil {
		t.Fatal(err)
	}
	loader := semanticLoaderFunc(func(file *os.File, manifest modelstore.Manifest) (detector.Semantic, error) {
		payload, err := io.ReadAll(file)
		if err != nil || string(payload) != "onnx-"+manifest.Version {
			return nil, errors.New("invalid model artifact")
		}
		if manifest.Version == "2.0.0" {
			return nil, errors.New("runtime rejected model")
		}
		return resourceSemantic{literalSemantic: literalSemantic("Alice"), usage: detector.SemanticResourceUsage{ResidentBytes: 64 << 20, WorkerCount: 2, Accelerator: "cpu", InferenceCount: 7}}, nil
	})
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	if err := s.WithModelStore(store); err != nil {
		t.Fatal(err)
	}
	if err := s.WithSemanticRuntime(loader, true); err != nil {
		t.Fatal(err)
	}
	matches, err := s.currentScanner().ScanChecked("/input", "hello Alice")
	if err != nil || len(matches) != 1 || matches[0].Finding.Detector != "semantic" {
		t.Fatalf("active semantic matches=%+v error=%v", matches, err)
	}
	inventoryRecorder := httptest.NewRecorder()
	s.listModels(inventoryRecorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	var inventory modelInventory
	if inventoryRecorder.Code != http.StatusOK || json.Unmarshal(inventoryRecorder.Body.Bytes(), &inventory) != nil || !inventory.Runtime.Connected || !inventory.Runtime.Required || !inventory.Runtime.Active || inventory.Runtime.ResourceState != "reported" || inventory.Runtime.Resources == nil || inventory.Runtime.Resources.ResidentBytes != 64<<20 || inventory.Runtime.Resources.WorkerCount != 2 || inventory.Runtime.Resources.Accelerator != "cpu" || inventory.Runtime.Resources.InferenceCount != 7 || inventory.Runtime.ArtifactBytes != int64(len("onnx-1.0.0")) {
		t.Fatalf("inventory status=%d value=%+v body=%s", inventoryRecorder.Code, inventory, inventoryRecorder.Body.String())
	}

	activate := httptest.NewRequest(http.MethodPut, "/v1/models/active", strings.NewReader(`{"version":"2.0.0"}`))
	activate.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.activateModel(recorder, activate)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("failed switch status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	file, active, err := store.OpenActive()
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if active.Version != "1.0.0" {
		t.Fatalf("failed switch changed active model to %q", active.Version)
	}
	matches, err = s.currentScanner().ScanChecked("/input", "hello Alice")
	if err != nil || len(matches) != 1 || matches[0].Finding.Detector != "semantic" {
		t.Fatalf("failed switch replaced scanner: matches=%+v error=%v", matches, err)
	}
}

func TestSemanticResourceUsageFailuresRemainExplicitAndBounded(t *testing.T) {
	for name, reporter := range map[string]detector.SemanticResourceReporter{
		"invalid": resourceSemantic{usage: detector.SemanticResourceUsage{Accelerator: "GPU 0"}},
		"error":   resourceSemantic{usage: detector.SemanticResourceUsage{Accelerator: "cpu"}, err: errors.New("private runtime path")},
		"panic":   resourceSemantic{panic: true},
	} {
		t.Run(name, func(t *testing.T) {
			if usage, err := readSemanticResourceUsage(reporter); err == nil || usage != (detector.SemanticResourceUsage{}) || strings.Contains(err.Error(), "private runtime path") {
				t.Fatalf("usage=%+v err=%v", usage, err)
			}
		})
	}
}

func TestRequiredSemanticRuntimeFailsClosedWithoutActiveModel(t *testing.T) {
	s, _ := New(session.NewManager(), "01234567890123456789012345678901")
	loader := semanticLoaderFunc(func(*os.File, modelstore.Manifest) (detector.Semantic, error) {
		return literalSemantic("Alice"), nil
	})
	if err := s.WithSemanticRuntime(loader, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.currentScanner().ScanChecked("/input", "ordinary text"); err == nil {
		t.Fatal("required semantic runtime silently allowed content without an active model")
	}
	recorder := httptest.NewRecorder()
	s.health(recorder, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var health map[string]string
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &health) != nil || health["status"] != "degraded" || health["semantic"] != "required_unavailable" {
		t.Fatalf("health=%+v status=%d body=%s", health, recorder.Code, recorder.Body.String())
	}
}
