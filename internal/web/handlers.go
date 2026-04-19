package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/trstudios/patch-pulse/internal/auth"
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
	CurrentDigest  string
	DiscoveredAt   time.Time
	LastSeenAt     time.Time
	ComposeProject string
	ComposeService string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	// Pull the current container roster from the DB. In v0.1-rebuild the
	// poller populates this; if the poller hasn't run yet we fall back to
	// a live Docker list so the dashboard is useful on the very first load.
	rows, err := s.DB.QueryContext(r.Context(),
		`SELECT container_id, name, image, tag, COALESCE(current_digest,''),
			COALESCE(compose_project,''), COALESCE(compose_service,''),
			discovered_at, last_seen_at
		FROM containers WHERE ignored = 0 ORDER BY name`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []dashboardRow
	for rows.Next() {
		var r dashboardRow
		var discUnix, seenUnix int64
		if err := rows.Scan(&r.ContainerID, &r.Name, &r.Image, &r.Tag, &r.CurrentDigest,
			&r.ComposeProject, &r.ComposeService, &discUnix, &seenUnix); err == nil {
			r.DiscoveredAt = time.Unix(discUnix, 0)
			r.LastSeenAt = time.Unix(seenUnix, 0)
			list = append(list, r)
		}
	}

	// Empty-state hint: has the poller actually run yet?
	var firstRunHint string
	if len(list) == 0 {
		if s.Docker != nil {
			firstRunHint = "No containers tracked yet. The first poll will populate this list within a minute — try refreshing."
		} else {
			firstRunHint = "Docker socket not mounted. Add /var/run/docker.sock:/var/run/docker.sock:ro to your compose file."
		}
	}

	s.renderPage(w, "PatchPulse — Dashboard", "dashboard-content", map[string]any{
		"User":         user,
		"Containers":   list,
		"FirstRunHint": firstRunHint,
	})
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

