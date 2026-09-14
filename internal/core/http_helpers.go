package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/agentveil/agentveil/internal/jsonsafe"
	"github.com/agentveil/agentveil/internal/modelstore"
	"github.com/agentveil/agentveil/internal/protocol"
)

func decodeManagement(r *http.Request, destination any) error {
	return decodeManagementWithLimit(r, destination, maxManagementBody)
}

func decodeManagementWithLimit(r *http.Request, destination any, limit int64) error {
	if r == nil || r.Body == nil || destination == nil || limit <= 0 {
		return errors.New("management request, destination, and positive size limit are required")
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !protocol.MediaTypeIs(contentTypes[0], "application/json") {
		return errors.New("management request requires one valid application/json content type")
	}
	encodings := r.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return errors.New("management request content encoding is unsupported or ambiguous")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("management request too large")
	}
	if err := jsonsafe.Validate(body); err != nil {
		return errors.New("management request contains invalid or ambiguous JSON")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("management request contains trailing data")
	}
	return nil
}

func decodeModelUpload(r *http.Request) (modelstore.Manifest, error) {
	if r == nil || r.Body == nil {
		return modelstore.Manifest{}, errors.New("model upload is required")
	}
	contentTypes := r.Header.Values("Content-Type")
	encodings := r.Header.Values("Content-Encoding")
	encodedManifests := r.Header.Values(ModelManifestHeader)
	if len(contentTypes) != 1 || !protocol.MediaTypeIs(contentTypes[0], "application/octet-stream") || len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") || len(encodedManifests) != 1 || len(encodedManifests[0]) > maxModelManifestHeaderBytes {
		return modelstore.Manifest{}, errors.New("model upload representation is invalid or ambiguous")
	}
	payload, err := base64.StdEncoding.DecodeString(encodedManifests[0])
	if err != nil || base64.StdEncoding.EncodeToString(payload) != encodedManifests[0] || len(payload) > maxModelManifestHeaderBytes || jsonsafe.Validate(payload) != nil {
		return modelstore.Manifest{}, errors.New("model manifest header is invalid")
	}
	var manifest modelstore.Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return modelstore.Manifest{}, errors.New("model manifest header is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return modelstore.Manifest{}, errors.New("model manifest header contains trailing data")
	}
	if manifest.Size <= 0 || manifest.Size > modelstore.MaxArtifactBytes || r.ContentLength != manifest.Size {
		return modelstore.Manifest{}, errors.New("model upload length does not match manifest")
	}
	return manifest, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	secureCoreResponseHeaders(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func secureCoreResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func ListenAddress(endpoint string) (string, error) {
	u := strings.TrimPrefix(endpoint, "http://")
	host, _, err := net.SplitHostPort(u)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return "", fmt.Errorf("core endpoint is not loopback: %s", endpoint)
	}
	return u, nil
}
