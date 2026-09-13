package core

import _ "embed"

// These files are the single dashboard source used by both the Core web panel
// and the Tauri desktop shell. Keeping them dependency-free avoids adding a
// frontend compilation step to every cross-platform package.

//go:embed webui/index.html
var dashboardShellHTML string

//go:embed webui/styles.css
var dashboardStyles string

//go:embed webui/app.js
var dashboardScript string
