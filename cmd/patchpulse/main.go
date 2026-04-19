// Command patchpulse — release notes + CVE context for Docker container updates.
//
// Runtime contract (matches tehrobot/docker-manager and every other
// TR Studios Unraid app):
//
//   - Single data directory at /config (single Docker volume mount).
//   - No YAML config files. Everything lives in /config/patchpulse.db
//     (SQLite), managed via the web Settings page.
//   - Zero-config first run: the binary starts, creates the DB, and
//     redirects you to /setup in the browser. If you set ADMIN_PASSWORD
//     as an env var we bootstrap the admin non-interactively (matches
//     docker-manager); otherwise the browser wizard does it.
//   - Binds 0.0.0.0 inside the container so Docker port mapping works.
//   - Runs as root inside the container (intentional; see Dockerfile
//     comment — we're not running PUID/PGID s6-overlay).
package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/trstudios/patch-pulse/internal/auth"
	"github.com/trstudios/patch-pulse/internal/db"
	"github.com/trstudios/patch-pulse/internal/dockercli"
	"github.com/trstudios/patch-pulse/internal/poller"
	"github.com/trstudios/patch-pulse/internal/web"
)

// Build-time metadata, overridable via -ldflags.
var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// --- Env -------------------------------------------------------------
	// CONFIG_PATH is the single data directory inside the container.
	// Default /config matches Unraid + tehrobot/docker-manager convention.
	configPath := envOr("CONFIG_PATH", "/config")
	port, _ := strconv.Atoi(envOr("PORT", "8921"))
	if port == 0 {
		port = 8921
	}
	dockerSocket := envOr("DOCKER_HOST", "/var/run/docker.sock")
	// Strip unix:// prefix if present (DOCKER_HOST convention).
	dockerSocket = stripUnixScheme(dockerSocket)

	envAdminUser := envOr("ADMIN_USERNAME", "admin")
	envAdminPass := os.Getenv("ADMIN_PASSWORD") // may be empty → web wizard takes over

	// --- DB --------------------------------------------------------------
	if err := os.MkdirAll(configPath, 0o755); err != nil {
		logger.Error("make config dir", "path", configPath, "err", err)
		os.Exit(1)
	}
	dbPath := filepath.Join(configPath, "patchpulse.db")
	database, err := db.Open(dbPath)
	if err != nil {
		logger.Error("open database", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer database.Close()

	// --- Admin bootstrap ------------------------------------------------
	ctx := context.Background()
	if err := auth.BootstrapAdminFromEnv(ctx, database, envAdminUser, envAdminPass); err != nil {
		logger.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}
	adminExists, _ := auth.AdminExists(ctx, database)
	if adminExists {
		if envAdminPass != "" {
			logger.Info("admin seeded from ADMIN_PASSWORD env", "username", envAdminUser)
		} else {
			logger.Info("admin already configured in DB")
		}
	} else {
		logger.Info("no admin yet — browse to the UI to create one via /setup")
	}

	// --- Docker client --------------------------------------------------
	docker := dockercli.NewClient(dockerSocket)

	// --- Poller ---------------------------------------------------------
	ctxRun, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	p := &poller.Poller{DB: database, Docker: docker, Logger: logger}
	go p.Run(ctxRun)

	// --- Web server -----------------------------------------------------
	srv, err := web.NewServer(database, logger, docker)
	if err != nil {
		logger.Error("init web server", "err", err)
		os.Exit(1)
	}
	listener, err := srv.Listen(port)
	if err != nil {
		logger.Error("bind port", "port", port, "err", err)
		os.Exit(1)
	}
	httpSrv := &http.Server{
		Handler:      srv.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("patchpulse starting",
		"version", version, "commit", commit, "buildTime", buildTime,
		"port", port, "config", configPath, "db", dbPath, "dockerSocket", dockerSocket)

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(listener) }()

	// --- Graceful shutdown on SIGINT/SIGTERM ----------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "err", err)
			os.Exit(1)
		}
	case s := <-sig:
		logger.Info("shutdown signal", "signal", s)
		cancelRun()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// stripUnixScheme removes "unix://" from the DOCKER_HOST env var if present.
// Our dockercli client wants a raw filesystem path.
func stripUnixScheme(s string) string {
	const p = "unix://"
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

func parseSQLOpenError(_ *sql.DB, err error) error { return err }

// Compile-time assertion that sql is imported even if unused by the main
// path (keeps the import gated if we ever strip features).
var _ = sql.ErrNoRows
