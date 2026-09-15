// Package webui owns the dependency-free Dashboard shared by browser and
// Tauri clients.
package webui

import (
	_ "embed"
	"io"
	"net/http"
)

//go:embed assets/index.html
var shellHTML string

//go:embed assets/styles.css
var styles string

//go:embed assets/audit.css
var auditStyles string

//go:embed assets/visibility.css
var visibilityStyles string

//go:embed assets/app.js
var applicationScript string

//go:embed assets/platform.js
var platformScript string

// Serve writes one immutable Dashboard asset and reports whether the path
// belongs to the UI.
func Serve(w http.ResponseWriter, r *http.Request) bool {
	if w == nil || r == nil {
		return false
	}
	switch r.URL.Path {
	case "/styles.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, styles)
	case "/audit.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, auditStyles)
	case "/visibility.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, visibilityStyles)
	case "/app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, applicationScript)
	case "/platform.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, platformScript)
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		_, _ = io.WriteString(w, shellHTML)
	default:
		return false
	}
	return true
}
