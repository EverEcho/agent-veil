package core

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
)

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	engine := s.policyEngine()
	writeJSON(w, http.StatusOK, policy.Document{SchemaVersion: "v1", Default: engine.Default, Rules: engine.Rules})
}

func (s *Server) listRulePacks(w http.ResponseWriter, _ *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	versions, err := s.ruleStore.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RULE_INVENTORY_FAILED"})
		return
	}
	inventory := rulePackInventory{Versions: versions}
	_, active, err := s.ruleStore.OpenActive()
	if err == nil {
		inventory.Active = active.Version
	} else if !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_RULE_INVALID"})
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (s *Server) installRulePack(w http.ResponseWriter, r *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	var request rulePackInstall
	if err := decodeManagementWithLimit(r, &request, maxRuleInstallBody); err != nil || request.ArtifactBase64 == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_RULE_PACK"})
		return
	}
	payload, err := base64.StdEncoding.DecodeString(request.ArtifactBase64)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != request.ArtifactBase64 || int64(len(payload)) != request.Manifest.Size {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_RULE_PACK"})
		return
	}
	if err := s.ruleStore.Install(request.Manifest, bytes.NewReader(payload)); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_INSTALLATION_FAILED"})
		return
	}
	writeJSON(w, http.StatusCreated, request.Manifest)
}

func (s *Server) activateRulePack(w http.ResponseWriter, r *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	var request struct {
		Version string `json:"version"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_RULE_VERSION"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	pack, _, err := s.ruleStore.Open(request.Version)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_ACTIVATION_FAILED"})
		return
	}
	base, err := detector.NewDefaultWithRulePack(pack)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_ACTIVATION_FAILED"})
		return
	}
	base.WithSemantic(s.semantic, s.semanticRequired)
	scanner, err := detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
	if err != nil || s.ruleStore.Activate(request.Version) != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_ACTIVATION_FAILED"})
		return
	}
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deactivateRulePack(w http.ResponseWriter, _ *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	base := detector.NewDefault().WithSemantic(s.semantic, s.semanticRequired)
	scanner, err := detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RULE_DEACTIVATION_FAILED"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	if err := s.ruleStore.Deactivate(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "RULE_DEACTIVATION_FAILED"})
		return
	}
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeRulePack(w http.ResponseWriter, r *http.Request) {
	if s.ruleStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "RULE_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	if err := s.ruleStore.Remove(r.PathValue("version")); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "RULE_REMOVAL_FAILED"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listModels(w http.ResponseWriter, _ *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	versions, err := s.modelStore.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_INVENTORY_FAILED"})
		return
	}
	inventory := modelInventory{Versions: versions}
	file, active, err := s.modelStore.OpenActive()
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_MODEL_INVALID"})
			return
		}
		inventory.Active = active.Version
		inventory.Runtime.ArtifactBytes = active.Size
	} else if !errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ACTIVE_MODEL_INVALID"})
		return
	}
	inventory.Runtime.Connected = s.semanticLoader != nil
	inventory.Runtime.Required = s.semanticRequired
	inventory.Runtime.Active = inventory.Active != "" && inventory.Active == s.semanticVersion && s.semantic != nil
	inventory.Runtime.ResourceState = "inactive"
	if inventory.Runtime.Active {
		inventory.Runtime.ResourceState = "unreported"
		if reporter, ok := s.semantic.(detector.SemanticResourceReporter); ok {
			usage, usageErr := readSemanticResourceUsage(reporter)
			if usageErr != nil {
				inventory.Runtime.ResourceState = "unavailable"
			} else {
				inventory.Runtime.ResourceState = "reported"
				inventory.Runtime.Resources = &usage
			}
		}
	}
	writeJSON(w, http.StatusOK, inventory)
}

func readSemanticResourceUsage(reporter detector.SemanticResourceReporter) (usage detector.SemanticResourceUsage, err error) {
	defer func() {
		if recover() != nil {
			usage = detector.SemanticResourceUsage{}
			err = domain.NewError(domain.ErrDetectorFailure, "read semantic resource usage", "semantic runtime panicked")
		}
	}()
	usage, err = reporter.SemanticResourceUsage()
	if err != nil {
		return detector.SemanticResourceUsage{}, domain.NewError(domain.ErrDetectorFailure, "read semantic resource usage", "semantic runtime metrics are unavailable")
	}
	if err := usage.Validate(); err != nil {
		return detector.SemanticResourceUsage{}, err
	}
	return usage, nil
}

func (s *Server) installModel(w http.ResponseWriter, r *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	manifest, err := decodeModelUpload(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_MODEL"})
		return
	}
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(maxModelUploadDuration)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_UPLOAD_FAILED"})
		return
	}
	if err := s.modelStore.Install(manifest, r.Body); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_INSTALLATION_FAILED"})
		return
	}
	writeJSON(w, http.StatusCreated, manifest)
}

func (s *Server) activateModel(w http.ResponseWriter, r *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	var request struct {
		Version string `json:"version"`
	}
	if err := decodeManagement(r, &request); err != nil || request.Version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_MODEL_VERSION"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	var semantic detector.Semantic
	if s.semanticLoader != nil {
		file, manifest, err := s.modelStore.Open(request.Version)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
			return
		}
		semantic, err = s.semanticLoader.Load(file, manifest)
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil || semantic == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
			return
		}
	}
	scanner, err := s.buildScannerLocked(semantic, s.semanticRequired)
	if err != nil || s.modelStore.Activate(request.Version) != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_ACTIVATION_FAILED"})
		return
	}
	s.semantic = semantic
	s.semanticVersion = ""
	if semantic != nil {
		s.semanticVersion = request.Version
	}
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deactivateModel(w http.ResponseWriter, _ *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	s.scannerMu.Lock()
	defer s.scannerMu.Unlock()
	scanner, err := s.buildScannerLocked(nil, s.semanticRequired)
	if err != nil || s.modelStore.Deactivate() != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MODEL_DEACTIVATION_FAILED"})
		return
	}
	s.semantic = nil
	s.semanticVersion = ""
	s.scanner = scanner
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeModel(w http.ResponseWriter, r *http.Request) {
	if s.modelStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "MODEL_STORE_UNAVAILABLE"})
		return
	}
	if err := s.modelStore.Remove(r.PathValue("version")); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MODEL_REMOVAL_FAILED"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentScanner() detector.ContentScanner {
	s.scannerMu.RLock()
	defer s.scannerMu.RUnlock()
	return s.scanner
}

func (s *Server) buildScannerLocked(semantic detector.Semantic, semanticRequired bool) (*detector.ChunkedScanner, error) {
	base := detector.NewDefault()
	if s.ruleStore != nil {
		pack, _, err := s.ruleStore.OpenActive()
		if err == nil {
			base, err = detector.NewDefaultWithRulePack(pack)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	base.WithSemantic(semantic, semanticRequired)
	return detector.NewChunked(base, detector.DefaultChunkBytes, detector.DefaultOverlapBytes)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	var document policy.Document
	if err := decodeManagement(r, &document); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_POLICY"})
		return
	}
	engine, err := document.Engine()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_POLICY"})
		return
	}
	s.policyMu.Lock()
	store := s.policyStore
	if store == nil {
		s.policyMu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "POLICY_STORE_UNAVAILABLE"})
		return
	}
	if err := store.Save(document); err != nil {
		s.policyMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "POLICY_SAVE_FAILED"})
		return
	}
	s.policy = engine
	s.policyMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) policyEngine() policy.Engine {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return policy.Engine{Default: s.policy.Default, Rules: append([]policy.Rule(nil), s.policy.Rules...)}
}
func (s *Server) resolveApproval(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Action domain.Action `json:"action"`
	}
	if err := decodeManagement(r, &request); err != nil || !s.broker.Resolve(r.PathValue("id"), request.Action) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "INVALID_APPROVAL"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
