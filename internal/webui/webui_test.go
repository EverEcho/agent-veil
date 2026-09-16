package webui

import (
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestDashboardServesAuditPreviewStyles(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) || !strings.Contains(page.Body.String(), `href="/audit.css"`) {
		t.Fatalf("dashboard does not load audit preview styles: %s", page.Body.String())
	}

	stylesheet := httptest.NewRecorder()
	if !Serve(stylesheet, httptest.NewRequest("GET", "/audit.css", nil)) || stylesheet.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(stylesheet.Body.String(), ".audit-preview") || !strings.Contains(stylesheet.Body.String(), ".settings-safety-note") {
		t.Fatalf("audit preview stylesheet was not served: headers=%v body=%s", stylesheet.Header(), stylesheet.Body.String())
	}
}

func TestDashboardUsesFixedDesktopShellWithPageScrolling(t *testing.T) {
	stylesheet := httptest.NewRecorder()
	if !Serve(stylesheet, httptest.NewRequest("GET", "/styles.css", nil)) {
		t.Fatal("dashboard stylesheet was not served")
	}
	body := stylesheet.Body.String()
	for _, want := range []string{`html { min-width: 320px; height: 100%; overflow: hidden;`, `.app-shell { height: 100%; overflow: hidden; }`, `main { max-width: 1560px; height: 100%;`, `.page { min-height: 0; padding-bottom: 40px; flex: 1;`, `overscroll-behavior: contain`, `scrollbar-gutter: stable`} {
		if !strings.Contains(body, want) {
			t.Fatalf("desktop shell scrolling contract is missing %q", want)
		}
	}
}

func TestDashboardToolCardsExposeInfoAndProtectedDesktopLaunch(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) || !strings.Contains(page.Body.String(), `href="/tools.css"`) {
		t.Fatal("dashboard does not load tool card styles")
	}

	stylesheet := httptest.NewRecorder()
	if !Serve(stylesheet, httptest.NewRequest("GET", "/tools.css", nil)) || stylesheet.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(stylesheet.Body.String(), ".tool-card-actions") {
		t.Fatalf("tool card stylesheet was not served: headers=%v body=%s", stylesheet.Header(), stylesheet.Body.String())
	}

	app := httptest.NewRecorder()
	if !Serve(app, httptest.NewRequest("GET", "/app.js", nil)) {
		t.Fatal("app asset was not served")
	}
	body := app.Body.String()
	for _, want := range []string{`class="tool-action tool-info"`, `data-launch-codex-desktop`, `class="tool-card-actions"`, `aria-label="${escapeHTML(t('tool.viewProtection'))}"`, `const restartIcon`, `const statePills = desktopProcess && (protectedRunning || running === true) ? processState : protectionState + processState`, `codex_desktop_running`, `codex_desktop_protected`, `t('process.restart')`, `from './i18n.js'`, `t('tool.description')`, `t('tool.viewProtection')`} {
		if !strings.Contains(body, want) {
			t.Fatalf("app asset does not contain %q", want)
		}
	}
	if strings.Contains(body, `${infoIcon}<span>`) || strings.Contains(body, `${playIcon}<span>`) {
		t.Fatal("tool card icon actions still render visible text labels")
	}
	if strings.Contains(body, `id="launch-codex-result"`) || strings.Contains(body, `在终端运行 <code>veil run`) {
		t.Fatal("tool detail still contains launch controls")
	}
}

func TestDashboardExposesSignedDesktopUpdateControls(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) || !strings.Contains(page.Body.String(), `id="update-channel"`) || !strings.Contains(page.Body.String(), `id="install-update"`) {
		t.Fatal("dashboard does not expose desktop update controls")
	}
	platform := httptest.NewRecorder()
	if !Serve(platform, httptest.NewRequest("GET", "/platform.js", nil)) || !strings.Contains(platform.Body.String(), "check_for_update") || !strings.Contains(platform.Body.String(), "install_update") {
		t.Fatal("desktop bridge does not expose update commands")
	}
}

func TestDashboardSeparatesPrivacyRulesFromGeneralSettings(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("dashboard was not served")
	}
	body := page.Body.String()
	privacyStart := strings.Index(body, `id="page-privacy"`)
	settingsStart := strings.Index(body, `id="page-settings"`)
	advancedStart := strings.Index(body, `id="page-advanced"`)
	if privacyStart < 0 || settingsStart <= privacyStart || advancedStart <= settingsStart {
		t.Fatal("privacy and settings pages are not independently defined")
	}
	privacy := body[privacyStart:settingsStart]
	settings := body[settingsStart:advancedStart]
	for _, want := range []string{`data-protection-setting="contact"`, `data-protection-setting="known-secrets"`, `id="private-key-action"`} {
		if !strings.Contains(privacy, want) {
			t.Fatalf("privacy page is missing %q", want)
		}
	}
	for _, misplaced := range []string{`id="locale"`, `id="auto-refresh"`, `id="update-card"`, `id="developer-enabled"`, `id="download-diagnostics"`} {
		if strings.Contains(privacy, misplaced) || !strings.Contains(settings, misplaced) {
			t.Fatalf("general setting %q is not isolated to the settings page", misplaced)
		}
	}
}

func TestDashboardExposesTruthfulStatusFunnelReasonsAndGroupedSearch(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("dashboard was not served")
	}
	for _, want := range []string{`id="dashboard-search-results"`, `aria-controls="dashboard-search-results"`, `data-i18n="shell.metricInstalled"`, `data-i18n="shell.metricActions"`, `>Privacy Core</span>`} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("dashboard shell is missing %q", want)
		}
	}
	if strings.Contains(page.Body.String(), `id="sidebar-status"`) || strings.Contains(page.Body.String(), `id="sidebar-dot"`) {
		t.Fatal("dashboard still duplicates Core health in the sidebar")
	}

	app := httptest.NewRecorder()
	if !Serve(app, httptest.NewRequest("GET", "/app.js", nil)) {
		t.Fatal("app asset was not served")
	}
	for _, want := range []string{`tool.status === 'verified'`, `state.agents.length`, `sessionCount()`, `event.error_code`, `event.finding_types`, `t('search.apps')`, `data-search-tool`, `data-search-event`} {
		if !strings.Contains(app.Body.String(), want) {
			t.Fatalf("dashboard behavior is missing %q", want)
		}
	}
}

func TestDashboardServesLocalI18nResources(t *testing.T) {
	i18n := httptest.NewRecorder()
	if !Serve(i18n, httptest.NewRequest("GET", "/i18n.js", nil)) || i18n.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || !strings.Contains(i18n.Body.String(), "export async function setLocale") {
		t.Fatalf("i18n layer was not served: headers=%v body=%s", i18n.Header(), i18n.Body.String())
	}

	for _, path := range []string{"/locales/zh-CN.json", "/locales/en.json"} {
		resource := httptest.NewRecorder()
		if !Serve(resource, httptest.NewRequest("GET", path, nil)) || resource.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("locale resource %s was not served: headers=%v", path, resource.Header())
		}
		var messages map[string]any
		if err := json.Unmarshal(resource.Body.Bytes(), &messages); err != nil {
			t.Fatalf("locale resource %s is invalid JSON: %v", path, err)
		}
		if messages["launch"] == nil || messages["tool"] == nil || messages["scope"] == nil {
			t.Fatalf("locale resource %s is missing required namespaces", path)
		}
	}
}

func TestDashboardExposesPrivateKeyPolicySelector(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) || !strings.Contains(page.Body.String(), `id="private-key-action"`) {
		t.Fatal("dashboard does not expose the private-key policy selector")
	}

	app := httptest.NewRecorder()
	if !Serve(app, httptest.NewRequest("GET", "/app.js", nil)) {
		t.Fatal("app asset was not served")
	}
	for _, want := range []string{"updatePrivateKeyAction", "'secret.private_key'", "policy.privateKeyRedact", "action !== latest.default"} {
		if !strings.Contains(app.Body.String(), want) {
			t.Fatalf("private-key policy selector is missing %q", want)
		}
	}
}

func TestDashboardExposesOptInDeveloperTraces(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("dashboard was not served")
	}
	for _, want := range []string{`id="developer-enabled"`, `id="developer-capture-bodies"`, `id="developer-trace-list"`, "权限为 0600", "256 KiB"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("developer settings are missing %q", want)
		}
	}
	app := httptest.NewRecorder()
	if !Serve(app, httptest.NewRequest("GET", "/app.js", nil)) {
		t.Fatal("app asset was not served")
	}
	for _, want := range []string{"/v1/developer-settings", "/v1/developer-traces", "renderDeveloperSettings", "request_before", "finding.match_bytes"} {
		if !strings.Contains(app.Body.String(), want) {
			t.Fatalf("developer trace UI is missing %q", want)
		}
	}
}

func TestDashboardStaticCopyUsesAvailableLocaleKeys(t *testing.T) {
	page := httptest.NewRecorder()
	if !Serve(page, httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("dashboard was not served")
	}
	matcher := regexp.MustCompile(`data-i18n(?:-placeholder|-aria)?="([^"]+)"`)
	matches := matcher.FindAllStringSubmatch(page.Body.String(), -1)
	if len(matches) == 0 {
		t.Fatal("dashboard does not expose localizable static copy")
	}
	for _, path := range []string{"/locales/zh-CN.json", "/locales/en.json"} {
		resource := httptest.NewRecorder()
		if !Serve(resource, httptest.NewRequest("GET", path, nil)) {
			t.Fatalf("locale %s was not served", path)
		}
		var messages map[string]any
		if err := json.Unmarshal(resource.Body.Bytes(), &messages); err != nil {
			t.Fatalf("locale %s is invalid JSON: %v", path, err)
		}
		for _, match := range matches {
			var value any = messages
			for _, segment := range strings.Split(match[1], ".") {
				object, ok := value.(map[string]any)
				if !ok {
					value = nil
					break
				}
				value = object[segment]
			}
			if text, ok := value.(string); !ok || text == "" {
				t.Errorf("locale %s is missing static copy key %q", path, match[1])
			}
		}
	}
}
