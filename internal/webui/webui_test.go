package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardServesAuditPreviewStyles(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) || !strings.Contains(page.Body.String(), `href="/audit.css"`) {
		t.Fatalf("dashboard does not load audit preview styles: %s", page.Body.String())
	}

	stylesheet := httptest.NewRecorder()
	if !Serve(stylesheet, httptest.NewRequest("GET", "/audit.css", nil)) || stylesheet.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(stylesheet.Body.String(), ".audit-preview") {
		t.Fatalf("audit preview stylesheet was not served: headers=%v body=%s", stylesheet.Header(), stylesheet.Body.String())
	}
}
