package web

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/trstudios/patch-pulse/internal/auth"
	"github.com/trstudios/patch-pulse/internal/cve"
	"github.com/trstudios/patch-pulse/internal/db"
	"github.com/trstudios/patch-pulse/internal/update"
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
	ContainerID     string
	Name            string
	Image           string
	Tag             string
	CurrentDigest   string // short form (first 12 chars after sha256:)
	LatestDigest    string // short form; empty if we haven't polled yet
	LatestCheckedAt time.Time
	Status          string // "up-to-date" | "update" | "unknown"
	CVECount        int    // -1 = not scanned yet
	CriticalCVE     int
	HighCVE         int
	DiscoveredAt    time.Time
	LastSeenAt      time.Time
	ComposeProject  string
	ComposeService  string
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

	// Count of ignored containers — powers the footer "Show N ignored" link.
	var ignoredCount int
	_ = s.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM containers WHERE ignored = 1`).Scan(&ignoredCount)

	// Last upstream check across any image — max(checked_at) from
	// upstream_versions. Drives the "last checked X ago" pill + the
	// client-side live timer.
	var lastCheckedUnix int64
	_ = s.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(MAX(checked_at), 0) FROM upstream_versions`).Scan(&lastCheckedUnix)
	var lastChecked time.Time
	if lastCheckedUnix > 0 {
		lastChecked = time.Unix(lastCheckedUnix, 0)
	}

	s.renderPage(w, "PatchPulse — Dashboard", "dashboard-content", map[string]any{
		"User":            user,
		"Containers":      list,
		"FirstRunHint":    firstRunHint,
		"Banners":         banners,
		"FlashCheck":      flashCheck,
		"IgnoredCount":    ignoredCount,
		"LastChecked":     lastChecked,
		"LastCheckedUnix": lastCheckedUnix,
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

// --- POST /container/{id}/ignore (toggle) -------------------------------

// handleContainerIgnoreToggle flips containers.ignored. Ignored containers
// are excluded from the dashboard, registry polling, and CVE scans — handy
// for noisy images (build-time sidecars, short-lived jobs) whose "update
// available" pings you don't care about. Idempotent toggle; redirects back
// to the detail page so the user can toggle back from there.
func (s *Server) handleContainerIgnoreToggle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	_, err := s.DB.ExecContext(ctx,
		`UPDATE containers SET ignored = CASE ignored WHEN 1 THEN 0 ELSE 1 END WHERE container_id = ?`, id)
	if err != nil {
		s.Logger.Warn("toggle ignore", "id", id, "err", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	// If we just ignored it, the detail page still resolves but dashboard
	// hides it. Send them back where they were.
	http.Redirect(w, r, "/container/"+id, http.StatusSeeOther)
}

// --- GET /ignored ---------------------------------------------------------

type ignoredRow struct {
	ContainerID string
	Name        string
	Image       string
	Tag         string
	LastSeenAt  time.Time
}

// handleIgnoredList shows every ignored container with a one-click
// un-ignore button. Intentionally bare — this is a "drawer" for hidden
// items, not a second dashboard.
func (s *Server) handleIgnoredList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT container_id, name, image, tag, last_seen_at
		FROM containers WHERE ignored = 1 ORDER BY name`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var list []ignoredRow
	for rows.Next() {
		var ir ignoredRow
		var seen int64
		if err := rows.Scan(&ir.ContainerID, &ir.Name, &ir.Image, &ir.Tag, &seen); err == nil {
			ir.LastSeenAt = time.Unix(seen, 0)
			list = append(list, ir)
		}
	}
	s.renderPage(w, "Ignored containers — PatchPulse", "ignored-content", map[string]any{
		"User":    auth.UserFromContext(r.Context()),
		"Ignored": list,
	})
}

// --- GET /export/cves.csv + /container/{id}/cves.csv ---------------------

// cveCSVColumns is the stable column order for both fleet and
// per-container exports. Don't reorder without considering consumers
// that pattern-match on column index (e.g. spreadsheets).
var cveCSVColumns = []string{
	"container_name", "image", "tag", "compose_project",
	"cve_id", "severity",
	"package_name", "package_version", "package_type",
	"fixed_version", "fix_state",
	"cve_url", "scanned_at",
}

var severityRank = map[string]int{
	"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4,
}

// writeCVECSV is the shared streamer for both export endpoints. Caller
// supplies the query cursor (already filtered to the right containers)
// and the CSV is flushed per-container so large exports start delivering
// bytes before the whole result set materialises.
func (s *Server) writeCVECSV(w http.ResponseWriter, filename string, rows *sql.Rows) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")

	cw := csv.NewWriter(w)
	_ = cw.Write(cveCSVColumns)

	for rows.Next() {
		var name, image, tag, composeProject, rawJSON string
		var scannedAt int64
		if err := rows.Scan(&name, &image, &tag, &composeProject, &rawJSON, &scannedAt); err != nil {
			continue
		}
		cves, err := cve.ParseCVEs(rawJSON)
		if err != nil {
			s.Logger.Warn("parse cves for export", "container", name, "err", err)
			continue
		}
		// Stable within-container ordering: severity (critical first), then id.
		sort.SliceStable(cves, func(i, j int) bool {
			ri, ok := severityRank[cves[i].Severity]
			if !ok {
				ri = 99
			}
			rj, ok := severityRank[cves[j].Severity]
			if !ok {
				rj = 99
			}
			if ri != rj {
				return ri < rj
			}
			return cves[i].ID < cves[j].ID
		})
		scannedISO := time.Unix(scannedAt, 0).UTC().Format(time.RFC3339)
		for _, c := range cves {
			_ = cw.Write([]string{
				name, image, tag, composeProject,
				c.ID, c.Severity,
				c.PackageName, c.PackageVersion, c.PackageType,
				c.FixedVersion, c.FixState,
				c.URL, scannedISO,
			})
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			s.Logger.Warn("csv export write failed", "err", err)
			return
		}
	}
	cw.Flush()
}

// handleCVEExport streams a CSV of every CVE across every non-ignored
// container that currently has a cached Grype scan. One row per finding
// (an image with N CVEs produces N rows). Containers without a scan yet
// are omitted — there's nothing to report.
//
// This is a read-only audit endpoint; auth middleware already gates it.
func (s *Server) handleCVEExport(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT c.name, c.image, c.tag, COALESCE(c.compose_project, ''),
		       cv.raw_json, cv.scanned_at
		FROM containers c
		JOIN cve_results cv ON cv.image_digest = c.current_digest
		WHERE c.ignored = 0
		ORDER BY c.name`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	s.writeCVECSV(w, "fleet.patch-pulse-export."+time.Now().Format("2006-01-02")+".csv", rows)
}

// handleContainerCVEExport streams the CSV for just the requested
// container. Rare to have > a few hundred rows here — no paging, full
// export in one shot.
func (s *Server) handleContainerCVEExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	// Look up the container name for the filename. The row itself is
	// also the existence check — if the container_id doesn't exist we
	// 404 rather than serve an empty CSV under a bogus filename.
	var cname string
	err := s.DB.QueryRowContext(r.Context(),
		`SELECT name FROM containers WHERE container_id = ?`, id).Scan(&cname)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	rows, err := s.DB.QueryContext(r.Context(), `
		SELECT c.name, c.image, c.tag, COALESCE(c.compose_project, ''),
		       cv.raw_json, cv.scanned_at
		FROM containers c
		JOIN cve_results cv ON cv.image_digest = c.current_digest
		WHERE c.container_id = ?`, id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	s.writeCVECSV(w,
		sanitiseFilenamePart(cname)+".patch-pulse-export."+time.Now().Format("2006-01-02")+".csv",
		rows)
}

// sanitiseFilenamePart makes an arbitrary string safe to embed in a
// Content-Disposition filename. Keeps letters/digits/dot/hyphen/
// underscore and replaces everything else with a hyphen. Prevents
// header-injection (CRLF) and filesystem-hostile chars (slashes) from
// leaking in via container names. Empty input returns "container".
func sanitiseFilenamePart(s string) string {
	if s == "" {
		return "container"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '.' || c == '-' || c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// --- POST /container/{id}/update -----------------------------------------

// handleContainerUpdate runs `docker compose pull && up -d <service>` for a
// compose-managed container, gated on:
//
//  1. Global "Enable update action" setting.
//  2. Compose path recorded for this project in settings.
//  3. User re-types the service name as an intent confirmation.
//
// CSRF covered by SameSite=Strict (same as /check). The service-name match
// is user-intent confirmation ("do you really want to update THIS"), not
// cross-site mitigation.
func (s *Server) handleContainerUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if !db.SettingGetBool(ctx, s.DB, db.KeyEnableUpdateAct, false) {
		http.Error(w, "update action disabled in Settings", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Pull container meta — need service + project + current digest.
	var name, project, service, currentDigest string
	err := s.DB.QueryRowContext(ctx, `
		SELECT name, COALESCE(compose_project,''), COALESCE(compose_service,''),
		       COALESCE(current_digest,'')
		FROM containers WHERE container_id = ?`, id).Scan(&name, &project, &service, &currentDigest)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if project == "" || service == "" {
		http.Error(w, "not a compose-managed container", http.StatusBadRequest)
		return
	}
	// Belt-and-braces: reject hostile identifiers even though compose.Run
	// also uses `--` to break out of flag parsing. The only way a hostile
	// value lands here is via a malicious container's own labels — which
	// already requires Docker socket access, but we gate anyway.
	if !update.IsSafeIdentifier(project) || !update.IsSafeIdentifier(service) {
		http.Error(w, "container labels contain unsafe characters", http.StatusBadRequest)
		return
	}
	// Intent confirmation: user re-types the service name.
	if strings.TrimSpace(r.FormValue("confirm")) != service {
		http.Redirect(w, r, "/container/"+id+"?update_err=confirm", http.StatusSeeOther)
		return
	}

	// Compose path for this project.
	var paths map[string]string
	_ = db.SettingGetJSON(ctx, s.DB, db.KeyComposePaths, &paths)
	composePath := paths[project]
	if composePath == "" {
		http.Redirect(w, r, "/container/"+id+"?update_err=nopath", http.StatusSeeOther)
		return
	}
	if !update.IsSafeComposePath(composePath) {
		http.Error(w, "configured compose path is not a safe absolute path", http.StatusBadRequest)
		return
	}

	// Detach the exec + audit from r.Context(). If the user closes their
	// browser tab mid-update, we do NOT want docker compose to get SIGKILL
	// halfway through a restart — that can leave the stack in a half-up
	// state. Cap the wall clock at 10 minutes regardless.
	runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	runner := update.DefaultRunner()
	res := runner.Run(runCtx, composePath, service)

	result := "ok"
	if res.Err != nil {
		result = "failed"
	}

	var userID int64
	if u := auth.UserFromContext(ctx); u != nil {
		userID = u.ID
	}
	// Audit insert also uses a fresh context so a late-aborting request
	// doesn't silently swallow the row.
	auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer auditCancel()
	_, _ = s.DB.ExecContext(auditCtx, `
		INSERT INTO actions (container_id, user_id, action, from_digest, result, detail, created_at)
		VALUES (?, ?, 'update', ?, ?, ?, ?)`,
		id, userID, currentDigest, result, res.Output, time.Now().Unix())

	http.Redirect(w, r, "/container/"+id+"?updated="+result, http.StatusSeeOther)
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
		rateLimited := !b.RateLimitedUntil.IsZero()
		b.Remediation = remediationFor(b.Adapter, b.LastError, rateLimited)
		out = append(out, b)
	}
	return out
}

// remediationFor returns the human-readable fix we'd show alongside a
// rate-limit or auth error. Keyed off the actual stored error text so a
// transient EOF doesn't get labelled as "rate limited", and an auth failure
// doesn't get labelled as "just wait it out".
func remediationFor(adapter, rawErr string, rateLimited bool) string {
	errLower := strings.ToLower(rawErr)

	// Rate-limit is the clearest signal: it was stored as such by the poller.
	if rateLimited || strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "http 429") {
		switch adapter {
		case "dockerhub":
			return "Docker Hub throttles anonymous pulls to 100 per 6 hours per IP. Retries resume automatically once the window resets."
		case "ghcr":
			return "GHCR is rate-limiting anonymous reads. Adding a GitHub PAT in Settings lifts the limit; otherwise retries resume automatically."
		case "quay":
			return "Quay.io is throttling us. Retries resume automatically; authenticating via the registry's web UI gives a higher limit."
		}
		return "Upstream registry is rate-limiting us. Retries resume automatically."
	}

	// Auth is the second clearest signal — user action is required.
	if strings.Contains(errLower, "authentication") || strings.Contains(errLower, "unauthorized") || strings.Contains(errLower, "http 401") || strings.Contains(errLower, "http 403") || strings.Contains(errLower, "private image") {
		switch adapter {
		case "ghcr":
			return "Private GHCR image or expired PAT. Add a GitHub personal access token in Settings → GitHub → Personal Access Token (classic token with `read:packages`, or fine-grained with Contents: Read)."
		case "dockerhub":
			return "Docker Hub returned an auth error. Check the image name is correct; private Docker Hub images need credentials (not yet supported in PatchPulse)."
		}
		return "Registry rejected the request as unauthorised. Check credentials in Settings."
	}

	// 404 / not found — likely a typo or a locally-tagged image Docker Hub
	// will never see. We already skip images with no RepoDigests, so this
	// usually means a pushed image was deleted upstream.
	if strings.Contains(errLower, "not found") || strings.Contains(errLower, "http 404") {
		return "Image isn't on " + adapter + " — it may have been deleted upstream, renamed, or tagged locally. Consider ignoring this container if it's a private build."
	}

	// Transient network / EOF / TLS — retry will recover.
	if strings.Contains(errLower, "unexpected eof") || strings.Contains(errLower, "timeout") || strings.Contains(errLower, "connection reset") || strings.Contains(errLower, "no such host") || strings.Contains(errLower, "tls") {
		return "Transient network error talking to " + adapter + ". Retries resume automatically; if it persists, check DNS / firewall from the container."
	}

	return "Upstream registry returned an error. Retries resume automatically."
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
	Ignored         bool
	Status          string
	Changelog       template.HTML // pre-sanitised by the poller
	ChangelogSource string
	ChangelogAt     time.Time
	CVEs            []cve.CVE
	CVEScannedAt    time.Time

	// Update-action UI state.
	UpdateEnabled    bool   // from Settings: "Enable update action"
	UpdateEligible   bool   // container is compose-managed AND we have its compose path
	ComposePath      string // resolved path for this project, if any
	UpdateLastOutput string // last run's captured output (from actions table)
	UpdateLastResult string // "ok" | "failed" | ""
	UpdateLastAt     time.Time
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
	var ignoredInt int
	err := s.DB.QueryRowContext(r.Context(), `
		SELECT container_id, name, image, tag,
		       COALESCE(current_digest, ''),
		       COALESCE(compose_project, ''), COALESCE(compose_service, ''),
		       ignored, discovered_at, last_seen_at
		FROM containers WHERE container_id = ?`, id).Scan(
		&d.ContainerID, &d.Name, &d.Image, &d.Tag,
		&currentDigestFull, &d.ComposeProject, &d.ComposeService,
		&ignoredInt, &discUnix, &seenUnix,
	)
	d.Ignored = ignoredInt == 1
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

	// Update-action eligibility: setting enabled + compose-managed + we
	// know the compose file path for this project.
	d.UpdateEnabled = db.SettingGetBool(r.Context(), s.DB, db.KeyEnableUpdateAct, false)
	if d.UpdateEnabled && d.ComposeProject != "" {
		var paths map[string]string
		_ = db.SettingGetJSON(r.Context(), s.DB, db.KeyComposePaths, &paths)
		if p, ok := paths[d.ComposeProject]; ok && p != "" {
			d.ComposePath = p
			d.UpdateEligible = true
		}
	}

	// Last update action for this container (most recent row in actions).
	var outStr, resultStr string
	var actAt int64
	_ = s.DB.QueryRowContext(r.Context(), `
		SELECT COALESCE(detail,''), COALESCE(result,''), created_at
		FROM actions WHERE container_id = ? AND action = 'update'
		ORDER BY created_at DESC LIMIT 1`, id).Scan(&outStr, &resultStr, &actAt)
	d.UpdateLastOutput = outStr
	d.UpdateLastResult = resultStr
	if actAt > 0 {
		d.UpdateLastAt = time.Unix(actAt, 0)
	}

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
		"Flash": map[string]string{
			"updated":    r.URL.Query().Get("updated"),    // "ok" | "failed" | ""
			"update_err": r.URL.Query().Get("update_err"), // "confirm" | "nopath" | ""
		},
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
	ComposePaths       map[string]string
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

	// Compose paths — one "project=/abs/path" per line. Empty project or
	// path entries are dropped. Future: validate that the path exists
	// inside the container before accepting.
	paths := map[string]string{}
	for _, line := range strings.Split(r.FormValue("compose_paths"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			continue
		}
		project := strings.TrimSpace(line[:eq])
		path := strings.TrimSpace(line[eq+1:])
		if project == "" || path == "" {
			continue
		}
		paths[project] = path
	}
	_ = db.SettingSetJSON(ctx, s.DB, db.KeyComposePaths, paths)

	_ = db.SettingSet(ctx, s.DB, db.KeyEnableUpdateAct, boolStr(r.FormValue("enable_update_action") == "on"))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyOnNewCVE, boolStr(r.FormValue("notify_on_new_cve") == "on"))
	_ = db.SettingSet(ctx, s.DB, db.KeyNotifyDailyDigest, boolStr(r.FormValue("notify_daily_digest") == "on"))

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) loadSettings(r *http.Request) settingsForm {
	ctx := r.Context()
	var urls []string
	_ = db.SettingGetJSON(ctx, s.DB, db.KeyAppriseURLs, &urls)
	var paths map[string]string
	_ = db.SettingGetJSON(ctx, s.DB, db.KeyComposePaths, &paths)
	if paths == nil {
		paths = map[string]string{}
	}
	token, _ := db.SettingGet(ctx, s.DB, db.KeyGitHubToken)
	return settingsForm{
		PollCadenceHours:   db.SettingGetInt(ctx, s.DB, db.KeyPollCadenceHours, 6),
		GitHubToken:        token,
		AppriseURLs:        urls,
		ComposePaths:       paths,
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
