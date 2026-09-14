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
	"path/filepath"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/instance"
	"github.com/agentveil/agentveil/internal/jsonsafe"
	"github.com/agentveil/agentveil/internal/protocol"
)

func managementJSON(ctx context.Context, method, target, token string, input, output any) error {
	return managementJSONWithTimeout(ctx, method, target, token, input, output, 10*time.Second)
}

func createBrowserTicket(ctx context.Context, endpoint, token string) (string, error) {
	var result struct {
		Ticket    string `json:"ticket"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := managementJSON(ctx, http.MethodPost, endpoint+"/v1/browser-sessions", token, nil, &result); err != nil {
		return "", err
	}
	if len(result.Ticket) != 43 || result.ExpiresAt == "" {
		return "", errors.New("Core returned an invalid browser session ticket")
	}
	for _, character := range result.Ticket {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return "", errors.New("Core returned an invalid browser session ticket")
	}
	return result.Ticket, nil
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
	response, err := managementHTTPClient(timeout).Do(request)
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

func managementHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
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
		if _, err := core.ListenAddress(explicit); err != nil {
			return "", err
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := verifyCoreIdentity(ctx, state.APIEndpoint, state.InstanceID); err != nil {
		return "", errors.New("AgentVeil Core state is stale or unavailable; start 'veil serve' or set VEIL_CORE_ENDPOINT")
	}
	return state.APIEndpoint, nil
}

func verifyCoreIdentity(ctx context.Context, endpoint, expectedInstanceID string) error {
	if ctx == nil || expectedInstanceID == "" {
		return domain.NewError(domain.ErrInvalidContract, "verify Core identity", "context and instance identity are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/identity", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set(core.APIVersionHeader, core.APIVersion)
	response, err := managementHTTPClient(2 * time.Second).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("Core identity endpoint is unavailable")
	}
	var identity struct {
		APIVersion string `json:"api_version"`
		InstanceID string `json:"instance_id"`
	}
	if err := decodeManagementResponse(response, &identity); err != nil {
		return err
	}
	if identity.APIVersion != core.APIVersion || identity.InstanceID != expectedInstanceID {
		return errors.New("Core identity does not match persisted state")
	}
	return nil
}
