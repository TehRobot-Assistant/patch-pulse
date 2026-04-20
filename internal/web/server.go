// Package web serves PatchPulse's HTTP UI. Three flows:
//
//  1. First-run /setup wizard — collects admin username + password
//     when no users exist yet. Redirected to for any request until
//     complete.
//  2. /login — session cookie issuer after admin exists.
//  3. Everything else — dashboard, container detail, settings,
//     update action. Gated by the auth middleware.
//
// All configuration that the old v0.1 expected in config.yml now lives
// in the SQLite settings table. The user edits it via the /settings
// page; changes take effect on the next poller tick, no restart.
package web

import (
	"bytes"
	"database/sql"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/trstudios/patch-pulse/internal/auth"
	"github.com/trstudios/patch-pulse/internal/dockercli"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds every dependency the handlers need. Construct via NewServer.
type Server struct {
	DB     *sql.DB
	Logger *slog.Logger
	Docker *dockercli.Client

	tpl *template.Template
}

// NewServer wires templates + helpers.
func NewServer(db *sql.DB, logger *slog.Logger, docker *dockercli.Client) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tplFS, err := fs.Sub(assets, "templates")
	if err != nil {
		return nil, err
	}
	// Build the template set with a `renderBody` helper that dispatches
	// dynamically to the per-page content template by name. Go's
	// html/template doesn't accept {{template .Body .}} because the
	// template name must be a string literal at parse time — this helper
	// works around that by looking up and executing the named template.
	//
	// The closure captures a `*template.Template` we populate after parse,
	// which works because the helper is only invoked at render time.
	var tpl *template.Template
	renderBody := func(name string, data any) (template.HTML, error) {
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, name, data); err != nil {
			return "", err
		}
		return template.HTML(buf.String()), nil
	}
	tpl = template.New("").Funcs(template.FuncMap{
		"fmtTime":    fmtTime,
		"agoT":       agoT,
		"upper":      upper,
		"renderBody": renderBody,
	})
	tpl, err = tpl.ParseFS(tplFS, "*.html")
	if err != nil {
		return nil, err
	}
	return &Server{DB: db, Logger: logger, Docker: docker, tpl: tpl}, nil
}

// Handler returns the fully-configured http.Handler (mux + middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public routes (accessible without a session).
	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("GET /health", s.handleHealth)

	// Authenticated routes.
	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /container/{id}", s.handleContainerDetail)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /settings", s.handleSettingsGet)
	mux.HandleFunc("POST /settings", s.handleSettingsPost)

	// Static assets.
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	return auth.Middleware(s.DB, mux)
}

// Listen returns a listener bound to 0.0.0.0:port. Inside the container
// we bind broadly; Docker's host-port mapping restricts external exposure.
// Binding to 127.0.0.1 inside the container would prevent port-forwarding
// from working at all — that was a v0.1 bug.
func (s *Server) Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", ":"+itoa(port))
}

// itoa avoids pulling strconv in a one-off.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// --- template helpers -----------------------------------------------------

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

func agoT(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return itoa(int(d.Hours())) + "h ago"
	default:
		return itoa(int(d.Hours())/24) + "d ago"
	}
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}
