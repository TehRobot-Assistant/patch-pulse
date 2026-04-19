// Package poller runs PatchPulse's background work — container
// discovery, upstream registry polls, changelog fetches, CVE scans.
//
// v0.1 (minimum lovable):
//   - Container discovery every 60s. Populates the containers table
//     so the dashboard immediately reflects what's running on the host.
//
// v0.2 (after dogfood validates the architecture):
//   - Registry polling every <poll_cadence_hours> hours
//   - Changelog fetcher when new digest detected
//   - Grype scan when current container digest changes
package poller

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"time"

	"github.com/trstudios/patch-pulse/internal/dockercli"
)

// Poller is the background job coordinator.
type Poller struct {
	DB     *sql.DB
	Docker *dockercli.Client
	Logger *slog.Logger
}

// Run starts the poller loop. Blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	// Fire a discovery pass immediately so the UI isn't empty for 60s
	// after first start.
	if err := p.discoverContainers(ctx); err != nil {
		p.Logger.Warn("initial container discovery failed", "err", err)
	}

	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := p.discoverContainers(ctx); err != nil {
				p.Logger.Warn("container discovery failed", "err", err)
			}
		}
	}
}

// discoverContainers pulls the current running-container list from Docker
// and upserts each row into the containers table. Also bumps last_seen_at
// so stale rows can be culled later.
func (p *Poller) discoverContainers(ctx context.Context) error {
	if p.Docker == nil {
		return nil
	}
	list, err := p.Docker.ListRunning(ctx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()

	for _, c := range list {
		image, tag := splitImageTag(c.ImageRef)
		composeProject := c.ComposeProject
		composeService := c.ComposeService

		_, err := p.DB.ExecContext(ctx, `
			INSERT INTO containers
			    (container_id, name, image, tag, current_digest, compose_project, compose_service,
			     discovered_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(container_id) DO UPDATE SET
			    name = excluded.name,
			    image = excluded.image,
			    tag = excluded.tag,
			    current_digest = excluded.current_digest,
			    compose_project = excluded.compose_project,
			    compose_service = excluded.compose_service,
			    last_seen_at = excluded.last_seen_at
		`, c.ID, c.Name, image, tag, c.ImageID, composeProject, composeService, now, now)
		if err != nil {
			p.Logger.Warn("upsert container", "id", c.ID, "err", err)
		}
	}
	return nil
}

// splitImageTag splits e.g. "nginx:1.25.0" into ("nginx", "1.25.0").
// If no tag is present, defaults to "latest".
func splitImageTag(ref string) (string, string) {
	// Strip any @sha256:... suffix; we care about the tag here.
	if at := strings.Index(ref, "@"); at > 0 {
		ref = ref[:at]
	}
	// Need to be careful: a registry with port has a colon too (e.g. ghcr.io:443/foo).
	// The tag, if present, comes after the last slash + colon.
	slash := strings.LastIndex(ref, "/")
	tagIdx := strings.LastIndex(ref, ":")
	if tagIdx == -1 || tagIdx < slash {
		return ref, "latest"
	}
	return ref[:tagIdx], ref[tagIdx+1:]
}
