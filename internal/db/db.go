// Package db owns the SQLite store. Everything the app stores long-term
// — users, settings, containers, observed versions, cached changelogs,
// cached CVE scans, action log — lives here. No YAML config anywhere.
package db

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, cross-compiles to ARM without CGO
)

// ErrNotFound signals "no row matched" in a friendly way.
var ErrNotFound = errors.New("not found")

// Open opens the SQLite file and runs all migrations. Safe to call on an
// empty file — the migrations create the schema from scratch.
func Open(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	d.SetMaxOpenConns(4)
	d.SetMaxIdleConns(2)
	if err := d.Ping(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(d); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// migrate applies every schema statement in order. Each is idempotent
// (CREATE IF NOT EXISTS, etc.) so running against an existing DB is a
// no-op. For real schema changes later we'd add a migrations table;
// v0.1 doesn't need it yet.
func migrate(d *sql.DB) error {
	for i, stmt := range schema {
		if _, err := d.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d: %w\nSQL: %s", i, err, stmt)
		}
	}
	return nil
}

var schema = []string{
	// --- Admin user(s). v0.1 has exactly one admin; leaving room for more. ---
	`CREATE TABLE IF NOT EXISTS users (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		username         TEXT    NOT NULL UNIQUE,
		password_hash    TEXT    NOT NULL,
		must_change      INTEGER NOT NULL DEFAULT 0,
		created_at       INTEGER NOT NULL
	)`,

	// --- Session cookies for the web UI. Cleaned up on logout + periodically. ---
	`CREATE TABLE IF NOT EXISTS sessions (
		token         TEXT    PRIMARY KEY,
		user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at    INTEGER NOT NULL,
		expires_at    INTEGER NOT NULL,
		last_used_at  INTEGER NOT NULL
	)`,

	// --- Arbitrary key/value settings (poll cadence, github token, apprise URLs, etc). ---
	`CREATE TABLE IF NOT EXISTS settings (
		key    TEXT PRIMARY KEY,
		value  TEXT NOT NULL
	)`,

	// --- Containers discovered on the host. Updated each discovery cycle. ---
	`CREATE TABLE IF NOT EXISTS containers (
		container_id      TEXT PRIMARY KEY,
		name              TEXT NOT NULL,
		image             TEXT NOT NULL,
		tag               TEXT NOT NULL,
		current_digest    TEXT,                -- manifest-list digest currently running
		compose_project   TEXT,                -- from com.docker.compose.project label
		compose_service   TEXT,                -- from com.docker.compose.service label
		ignored           INTEGER NOT NULL DEFAULT 0,
		notify_only       INTEGER NOT NULL DEFAULT 0,
		discovered_at     INTEGER NOT NULL,
		last_seen_at      INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_containers_image ON containers (image, tag)`,

	// --- OCI image metadata per image:tag. Populated by the poller via Docker
	// InspectImage. Used by the changelog fetcher to know which GitHub repo
	// to query (org.opencontainers.image.source). ---
	`CREATE TABLE IF NOT EXISTS image_meta (
		image            TEXT NOT NULL,
		tag              TEXT NOT NULL,
		source_url       TEXT,                  -- org.opencontainers.image.source
		inspected_at     INTEGER NOT NULL,
		PRIMARY KEY (image, tag)
	)`,

	// --- Upstream versions seen per image:tag. New row when a new digest appears. ---
	`CREATE TABLE IF NOT EXISTS upstream_versions (
		image            TEXT NOT NULL,
		tag              TEXT NOT NULL,
		digest           TEXT NOT NULL,
		first_seen_at    INTEGER NOT NULL,
		checked_at       INTEGER NOT NULL,
		PRIMARY KEY (image, tag, digest)
	)`,

	// --- Cached release notes per image version. Expire after N days. ---
	`CREATE TABLE IF NOT EXISTS changelogs (
		image            TEXT NOT NULL,
		tag              TEXT NOT NULL,
		source           TEXT,                  -- github-releases | changelog-md | commit-log
		markdown         TEXT,                  -- raw markdown, sanitised at render time
		fetched_at       INTEGER NOT NULL,
		PRIMARY KEY (image, tag)
	)`,

	// --- Cached Grype results per image digest. ---
	`CREATE TABLE IF NOT EXISTS cve_results (
		image_digest    TEXT PRIMARY KEY,
		raw_json        TEXT NOT NULL,        -- full Grype JSON output
		scanned_at      INTEGER NOT NULL
	)`,

	// --- Audit log of every Update action (manual-trigger only in v0.1). ---
	`CREATE TABLE IF NOT EXISTS actions (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		container_id     TEXT,
		user_id          INTEGER,
		action           TEXT NOT NULL,        -- "update" | "ignore" | "unignore"
		from_digest      TEXT,
		to_digest        TEXT,
		result           TEXT,                  -- "ok" | "failed"
		detail           TEXT,
		created_at       INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_actions_container ON actions (container_id, created_at DESC)`,
}
