package web

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/trstudios/patch-pulse/internal/auth"
	"github.com/trstudios/patch-pulse/internal/cve"
	"github.com/trstudios/patch-pulse/internal/db"
)

// --- /setup (first-run admin bootstrap) -----------------------------------

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	exists, err := auth.AdminExists(r.Context(), s.DB)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	if exists {
		// Setup is one-shot; once an admin exists you must go through /login.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderPage(w, "PatchPulse — First-Run Setup", "setup-content",
		map[string]any{"Error": ""})
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	exists, _ := auth.AdminExists(r.Context(), s.DB)
	if exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if password != confirm {
		s.renderPage(w, "PatchPulse — First-Run Setup", "setup-content",
			map[string]any{"Error": "Passwords don't match.", "Username": username})
		return
	}
	user, err := auth.CreateAdmin(r.Context(), s.DB, username, password)
	if err != nil {
		s.renderPage(w, "PatchPulse — First-Run Setup", "setup-content",
		map[string]any{"Error": err.Error(), "Username": username})
		return
	}
	// Auto-login the newly-created admin.
	tok, err := auth.CreateSession(r.Context(), s.DB, user.ID)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- /login + /logout -----------------------------------------------------

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	// If already logged in, shortcut to dashboard.
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
		if user, err := auth.LookupSession(r.Context(), s.DB, cookie.Value); err == nil && user != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	s.renderPage(w, "Sign in — PatchPulse", "login-content", map[string]any{"Error": ""})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	user, err := auth.Authenticate(r.Context(), s.DB, username, password)
	if err != nil {
		// Deliberately vague error — don't leak which field was wrong.
		s.renderPage(w, "Sign in — PatchPulse", "login-content",
			map[string]any{"Error": "Invalid username or password.", "Username": username})
		return
	}
	tok, err := auth.CreateSession(r.Context(), s.DB, user.ID)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
		_ = auth.DeleteSession(r.Context(), s.DB, cookie.Value)
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- /health -------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.PingContext(r.Context()); err != nil {
		http.Error(w, "db down", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"ts":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
}

// --- / (dashboard) --------------------------------------------------------

type dashboardRow struct {
	ContainerID    string
	Name           string
	Image          string
	Tag            string
	CurrentDigest  string    // short form (first 12 chars after sha256:)
	LatestDigest   string    // short form; empty if we haven't polled yet
	LatestCheckedAt time.Time
	Status         string    // "up-to-date" | "update" | "unknown"
	CVECount       int       // -1 = not scanned yet
	CriticalCVE    int
	HighCVE        int
	DiscoveredAt   time.Time
	LastSeenAt     time.Time
	ComposeProject string
	ComposeService string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	// Enriched query: joins the most recent upstream digest + the Grype
	// scan (if any) onto each container row. The upstream join uses the
	// per-(image,tag) max(checked_at) row so we always see the newest digest
	// the poller has observed.
	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT c.container_id, c.name, c.image, c.tag,
		       COALESCE(c.current_digest, ''),
		       COALESCE(c.compose_project, ''), COALESCE(c.compose_service, ''),
		       c.discovered_at, c.last_seen_at,
		       COALESCE(uv.digest, ''),
		       COALESCE(uv.checked_at, 0),
		       cv.raw_json
		FROM containers c
		LEFT JOIN (
		    SELECT image, tag, digest, checked_at
		    FROM upstream_versions uv1
		    WHERE checked_at = (
		        SELECT MAX(checked_at) FROM upstream_versions uv2
		        WHERE uv2.image = uv1.image AND uv2.tag = uv1.tag
		    )
		) uv ON uv.image = c.image AND uv.tag = c.tag
		LEFT JOIN cve_results cv ON cv.image_digest = c.current_digest
		WHERE c.ignored = 0
		ORDER BY c.name
	`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []dashboardRow
	for rows.Next() {
		var row dashboardRow
		var discUnix, seenUnix, checkedUnix int64
		var cveJSON *string
		if err := rows.Scan(
			&row.ContainerID, &row.Name, &row.Image, &row.Tag,
			&row.CurrentDigest, &row.ComposeProject, &row.ComposeService,
			&discUnix, &seenUnix,
			&row.LatestDigest, &checkedUnix, &cveJSON,
		); err != nil {
			continue
		}
		row.DiscoveredAt = time.Unix(discUnix, 0)
		row.LastSeenAt = time.Unix(seenUnix, 0)
		if checkedUnix > 0 {
			row.LatestCheckedAt = time.Unix(checkedUnix, 0)
		}

		// Status: only "up-to-date" vs "update" when we have BOTH digests.
		// Missing either side → "unknown" and the UI greys the chip.
		switch {
		case row.LatestDigest == "" || row.CurrentDigest == "":
			row.Status = "unknown"
		case row.LatestDigest == row.CurrentDigest:
			row.Status = "up-to-date"
		default:
			row.Status = "update"
		}

		// Short-form digests for display.
		row.CurrentDigest = shortDigest(row.CurrentDigest)
		row.LatestDigest = shortDigest(row.LatestDigest)

		// CVE counts — only meaningful if we've scanned this digest.
		row.CVECount = -1
		if cveJSON != nil && *cveJSON != "" {
			if cves, err := cve.ParseCVEs(*cveJSON); err == nil {
				row.CVECount = len(cves)
				for _, c := range cves {
					switch c.Severity {
					case "Critical":
						row.CriticalCVE++
					case "High":
						row.HighCVE++
					}
				}
			}
		}

		list = append(list, row)
	}

	var firstRunHint string
	if len(list) == 0 {
		firstRunHint = "No containers tracked yet. The first poll will populate this list within a minute — try refreshing."
	}

	// Rate-limit / last-error banners.
	banners := s.loadRegistryBanners(r.Context())

	// One-shot flash from /check redirect.
	flashCheck := r.URL.Query().Get("checked") == "1"

	s.renderPage(w, "PatchPulse — Dashboard", "dashboard-content", map[string]any{
		"User":         user,
		"Containers":   list,
		"FirstRunHint": firstRunHint,
		"Banners":      banners,
		"FlashCheck":   flashCheck,
	})
}

// --- /check (Force check) -------------------------------------------------

// handleForceCheck signals the poller to run an upstream pass right now.
// No CSRF token required: the session cookie is issued with SameSite=Strict
// (see auth.SetSessionCookie), which browsers won't send on cross-site POSTs.
// Good enough for a home-server single-user app; revisit if we add
// multi-user write actions exposed to untrusted referrers.
func (s *Server) handleForceCheck(w http.ResponseWriter, r *http.Request) {
	if s.Poller != nil {
		s.Poller.TriggerCheck()
	}
	http.Redirect(w, r, "/?checked=1", http.StatusSeeOther)
}

// registryBanner is a rate-limit or last-error card shown on the dashboard
// with a remediation hint. Only loaded when the adapter actually has state
// to surface — a clean table yields no banners.
type registryBanner struct {
	Adapter          string    // "dockerhub" | "ghcr" | "quay"
	RateLimitedUntil time.Time // zero if not rate-limited
	LastError        string
	LastErrorAt      time.Time
	Remediation      string // human-readable suggestion
}

func (s *Server) loadRegistryBanners(ctx context.Context) []registryBanner {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT adapter, rate_limited_until, COALESCE(last_error, ''), last_error_at
		FROM registry_state
		WHERE rate_limited_until > ? OR last_error IS NOT NULL`, time.Now().Unix())
	if err != nil {
		s.Logger.Warn("load registry banners", "err", err)
		return nil
	}
	defer rows.Close()
	var out []registryBanner
	for rows.Next() {
		var b registryBanner
		var until, errAt int64
		if err := rows.Scan(&b.Adapter, &until, &b.LastError, &errAt); err != nil {
			continue
		}
		if until > 0 {
			b.RateLimitedUntil = time.Unix(until, 0)
		}
		if errAt > 0 {
			b.LastErrorAt = time.Unix(errAt, 0)
		}
		b.Remediation = remediationFor(b.Adapter)
		out = append(out, b)
	}
	return out
}

// remediationFor returns the human-readable fix we'd show alongside a
// rate-limit or auth error. Single source of truth for these strings; the
// poller stores the raw condition only.
func remediationFor(adapter string) string {
	switch adapter {
	case "ghcr":
		return "Add a GitHub personal access token in Settings → \"GitHub PAT\". Any classic token with `public_repo` scope (or a fine-grained token with Contents: Read on public repos) will do."
	case "dockerhub":
		return "Docker Hub throttles anonymous pulls to 100 per 6 hours per IP. The next check will happen automatically once the window resets — no action needed."
	case "quay":
		return "Quay.io is throttling us. Retries will resume automatically; if it persists, authenticate via the registry's web UI for a higher limit."
	default:
		return "Upstream registry is returning errors. Retries will resume automatically."
	}
}

// --- /container/{id} (detail) ---------------------------------------------

type containerDetail struct {
	ContainerID     string
	Name            string
	Image           string
	Tag             string
	CurrentDigest   string
	LatestDigest    string
	LatestCheckedAt time.Time
	LastSeenAt      time.Time
	ComposeProject  string
	ComposeService  string
	Status          string
	Changelog       template.HTML // pre-sanitised by the poller
	ChangelogSource string
	ChangelogAt     time.Time
	CVEs            []cve.CVE
	CVEScannedAt    time.Time
}

func (s *Server) handleContainerDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	var d containerDetail
	var discUnix, seenUnix int64
	var currentDigestFull string
	err := s.DB.QueryRowContext(r.Context(), `
		SELECT container_id, name, image, tag,
		       COALESCE(current_digest, ''),
		       COALESCE(compose_project, ''), COALESCE(compose_service, ''),
		       discovered_at, last_seen_at
		FROM containers WHERE container_id = ?`, id).Scan(
		&d.ContainerID, &d.Name, &d.Image, &d.Tag,
		&currentDigestFull, &d.ComposeProject, &d.ComposeService,
		&discUnix, &seenUnix,
	)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d.LastSeenAt = time.Unix(seenUnix, 0)

	// Latest upstream digest.
	var latestFull string
	var checkedUnix int64
	_ = s.DB.QueryRowContext(r.Context(), `
		SELECT digest, checked_at
		FROM upstream_versions
		WHERE image = ? AND tag = ?
		ORDER BY checked_at DESC LIMIT 1`, d.Image, d.Tag).Scan(&latestFull, &checkedUnix)
	if checkedUnix > 0 {
		d.LatestCheckedAt = time.Unix(checkedUnix, 0)
	}

	switch {
	case latestFull == "" || currentDigestFull == "":
		d.Status = "unknown"
	case latestFull == currentDigestFull:
		d.Status = "up-to-date"
	default:
		d.Status = "update"
	}
	d.CurrentDigest = shortDigest(currentDigestFull)
	d.LatestDigest = shortDigest(latestFull)

	// Changelog cached by the poller (already sanitised HTML).
	var changelogHTML, clSource string
	var clAt int64
	_ = s.DB.QueryRowContext(r.Context(), `
		SELECT COALESCE(markdown,''), COALESCE(source,''), fetched_at
		FROM changelogs WHERE image = ? AND tag = ?`, d.Image, d.Tag,
	).Scan(&changelogHTML, &clSource, &clAt)
	d.Changelog = template.HTML(changelogHTML)
	d.ChangelogSource = clSource
	if clAt > 0 {
		d.ChangelogAt = time.Unix(clAt, 0)
	}

	// CVE list.
	if currentDigestFull != "" {
		var rawJSON string
		var scanAt int64
		err := s.DB.QueryRowContext(r.Context(),
			`SELECT raw_json, scanned_at FROM cve_results WHERE image_digest = ?`,
			currentDigestFull).Scan(&rawJSON, &scanAt)
		if err == nil {
			if cves, err := cve.ParseCVEs(rawJSON); err == nil {
				d.CVEs = cves
			}
			d.CVEScannedAt = time.Unix(scanAt, 0)
		}
	}

	s.renderPage(w, "PatchPulse — "+d.Name, "container-content", map[string]any{
		"User":      auth.UserFromContext(r.Context()),
		"Container": d,
	})
}

// shortDigest trims sha256: prefix and truncates to 12 chars.
func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// --- /settings ------------------------------------------------------------

type settingsForm struct {
	PollCadenceHours   int
	GitHubToken        string
	AppriseURLs        []string
	EnableUpdateAction bool
	NotifyOnNewCVE     bool
	NotifyDailyDigest  bool
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	f := s.loadSettings(r)
	s.renderPage(w, "Settings — PatchPulse", "settings-content", map[string]any{
		"User":     auth.UserFromContext(r.Context()),
		"Settings": f,
		"Saved":    r.URL.Query().Get("saved") != "",
	})
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()

	cadence := r.FormValue("poll_cadence_hours")
	if _, err := parsePositiveInt(cadence); err == nil {
		_ = db.SettingSet(ctx, s.DB, db.KeyPollCadenceHours, cadence)
	}

	_ = db.SettingSet(ctx, s.DB, db.KeyGitHubToken, strings.TrimSpace(r.FormValue("github_token")))

	appriseRaw := strings.TrimSpace(r.FormValue("apprise_urls"))
	urls := []string{}
	for _, line := range strings.Split(appriseRaw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	_ = db.SettingSetJSON(ctx, s.DB, db.KeyAppriseURLs, urls)

	_ = db.SettingSet(ctx, s.DB, db.KeyEnableUpdateAct, boolStr(r.FormValue("enable_update_action") == "on"))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyOnNewCVE, boolStr(r.FormValue("notify_on_new_cve") == "on"))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyDailyDigest, boolStr(r.FormValue("notify_daily_digest") == "on"))

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) loadSettings(r *http.Request) settingsForm {
	ctx := r.Context()
	var urls []string
	_ = db.SettingGetJSON(ctx, s.DB, db.KeyAppriseURLs, &urls)
	token, _ := db.SettingGet(ctx, s.DB, db.KeyGitHubToken)
	return settingsForm{
		PollCadenceHours:   db.SettingGetInt(ctx, s.DB, db.KeyPollCadenceHours, 6),
		GitHubToken:        token,
		AppriseURLs:        urls,
		EnableUpdateAction: db.SettingGetBool(ctx, s.DB, db.KeyEnableUpdateAct, false),
		NotifyOnNewCVE:     db.SettingGetBool(ctx, s.DB, db.KeyNotifyOnNewCVE, true),
		NotifyDailyDigest:  db.SettingGetBool(ctx, s.DB, db.KeyNotifyDailyDigest, true),
	}
}

// --- helpers --------------------------------------------------------------

// renderPage wraps a page in the shared "layout" template. The body
// template name is injected into the data map under key "Body" (+ "Title")
// so the layout can dispatch dynamically via {{template .Body .}}.
func (s *Server) renderPage(w http.ResponseWriter, title, bodyTemplate string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	data["Body"] = bodyTemplate
	if _, hasUser := data["User"]; !hasUser {
		data["User"] = nil // layout checks `{{if .User}}` for header
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.Logger.Error("render", "body", bodyTemplate, "err", err)
	}
}

func parsePositiveInt(str string) (int, error) {
	if str == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for _, c := range str {
		if c < '0' || c > '9' {
			return 0, errors.New("not numeric")
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 0, errors.New("must be positive")
	}
	return n, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

