package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Settings key constants — single source of truth for what a key is called
// anywhere in the app.
const (
	KeyPollCadenceHours  = "poll_cadence_hours"
	KeyGitHubToken       = "github_token"
	KeyAppriseURLs       = "apprise_urls"  // JSON array of strings
	KeyComposePaths      = "compose_paths" // JSON object: project → abs-path
	KeyEnableUpdateAct   = "enable_update_action"
	KeyNotifyOnNewCVE    = "notify_on_new_cve"
	KeyNotifyDailyDigest = "notify_daily_digest"
)

// Defaults ship with the app. User can override via Settings UI.
var Defaults = map[string]string{
	KeyPollCadenceHours:  "6",
	KeyGitHubToken:       "",
	KeyAppriseURLs:       "[]",
	KeyComposePaths:      "{}",
	KeyEnableUpdateAct:   "false",
	KeyNotifyOnNewCVE:    "true",
	KeyNotifyDailyDigest: "true",
}

// SettingGet returns the stored value for a key, or the default if not set.
func SettingGet(ctx context.Context, d *sql.DB, key string) (string, error) {
	var v string
	err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if def, ok := Defaults[key]; ok {
			return def, nil
		}
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("setting %q: %w", key, err)
	}
	return v, nil
}

// SettingSet upserts a setting.
func SettingSet(ctx context.Context, d *sql.DB, key, value string) error {
	_, err := d.ExecContext(ctx, `
		INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

// SettingGetJSON decodes a JSON-shaped setting (arrays, objects) into out.
func SettingGetJSON(ctx context.Context, d *sql.DB, key string, out any) error {
	v, err := SettingGet(ctx, d, key)
	if err != nil {
		return err
	}
	if v == "" {
		return nil
	}
	return json.Unmarshal([]byte(v), out)
}

// SettingSetJSON encodes + stores a JSON-shaped setting.
func SettingSetJSON(ctx context.Context, d *sql.DB, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return SettingSet(ctx, d, key, string(b))
}

// SettingGetInt returns the setting as int, or the default if not set.
func SettingGetInt(ctx context.Context, d *sql.DB, key string, fallback int) int {
	v, err := SettingGet(ctx, d, key)
	if err != nil || v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}

// SettingGetBool returns the setting as bool.
func SettingGetBool(ctx context.Context, d *sql.DB, key string, fallback bool) bool {
	v, _ := SettingGet(ctx, d, key)
	switch v {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return fallback
}
