// Package notify fans notifications out via Apprise. Apprise is installed
// as a subprocess inside the container (apt install apprise) and accepts
// 110+ service URLs (ntfy, Gotify, Discord, Slack, Telegram, email, SMS).
// We shell out rather than reimplementing any of them.
package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Level categorises a notification for rendering + routing.
type Level string

const (
	LevelInfo    Level = "info"
	LevelSuccess Level = "success"
	LevelWarn    Level = "warning"
	LevelError   Level = "failure"
)

// Client wraps Apprise CLI invocations.
type Client struct {
	binary string
	urls   []string
}

// New returns a Client. If binary is empty, "apprise" is looked up in PATH.
// If no URLs are configured the Client is a no-op; Send returns nil.
func New(binary string, urls []string) (*Client, error) {
	if binary == "" {
		binary = "apprise"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("apprise not found: %w", err)
	}
	return &Client{binary: binary, urls: urls}, nil
}

// Send dispatches a notification. No-op when no URLs are configured.
func (c *Client) Send(ctx context.Context, level Level, title, body string) error {
	if c == nil || len(c.urls) == 0 {
		return nil
	}
	args := []string{"-t", title, "-b", body, "-n", string(level)}
	args = append(args, c.urls...)

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, c.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apprise: %w: %s", err, stderr.String())
	}
	return nil
}

// Enabled reports whether the client will actually send anything.
func (c *Client) Enabled() bool { return c != nil && len(c.urls) > 0 }

// ErrNoApprise is returned if the Apprise binary is missing. Callers
// that encounter this typically just fall back to no notifications.
var ErrNoApprise = errors.New("apprise binary not found in PATH")
