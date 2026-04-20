// Package poller runs PatchPulse's background work.
//
// Three concurrent loops, all respect ctx:
//
//  1. Discovery (60s)            — list running containers, upsert rows,
//     capture current image digest + OCI
//     labels for each unique image:tag.
//  2. Upstream (poll_cadence_hours from settings, default 6h) — for every
//     unique image:tag currently running, hit the correct registry
//     adapter (Docker Hub / GHCR / Quay) to resolve the latest manifest
//     digest, and insert a row into upstream_versions whenever we see a
//     digest we haven't seen before. When a newly-observed upstream
//     digest differs from what's running, fire a notification and try to
//     fetch the changelog via GitHub.
//  3. CVE scan (15m sweep)       — for any container whose current_digest
//     has no cached Grype result, run a scan and cache the JSON. Skipped
//     entirely if grype wasn't found on PATH at startup.
//
// Everything is idempotent on restart: the DB is the source of truth.
package poller

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/trstudios/patch-pulse/internal/changelog"
	"github.com/trstudios/patch-pulse/internal/cve"
	"github.com/trstudios/patch-pulse/internal/db"
	"github.com/trstudios/patch-pulse/internal/dockercli"
	"github.com/trstudios/patch-pulse/internal/notify"
	"github.com/trstudios/patch-pulse/internal/registry"
)

// Poller is the background job coordinator. Wire everything nilable at
// construction — a missing grype binary just disables CVE scanning, a
// missing apprise binary just disables notifications.
type Poller struct {
	DB       *sql.DB
	Docker   *dockercli.Client
	Logger   *slog.Logger
	Registry *registry.Registry // required
	Scanner  *cve.Scanner       // may be nil

	// triggerCheck is a signal channel the web UI's "Force check" button
	// writes to, causing the upstream loop to run a check immediately
	// regardless of cadence. Buffered size 1 = multiple quick clicks just
	// coalesce into a single extra pass.
	triggerCheck chan struct{}
	initOnce     sync.Once
}

// TriggerCheck signals the upstream loop to run an immediate poll pass.
// Safe to call from any goroutine; multiple calls during one in-flight
// pass coalesce into a single extra check.
func (p *Poller) TriggerCheck() {
	p.ensureChan()
	select {
	case p.triggerCheck <- struct{}{}:
	default:
		// Already a pending trigger — drop this one.
	}
}

func (p *Poller) ensureChan() {
	p.initOnce.Do(func() {
		p.triggerCheck = make(chan struct{}, 1)
	})
}

// Run starts all three loops. Blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	p.ensureChan()
	// Discovery runs first, synchronously, so the dashboard is never blank.
	if err := p.discoverContainers(ctx); err != nil {
		p.Logger.Warn("initial container discovery failed", "err", err)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); p.discoveryLoop(ctx) }()
	go func() { defer wg.Done(); p.upstreamLoop(ctx) }()
	go func() { defer wg.Done(); p.cveLoop(ctx) }()
	wg.Wait()
}

// --- loop 1: discovery ------------------------------------------------------

func (p *Poller) discoveryLoop(ctx context.Context) {
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
// and upserts each row into the containers table. Also fills image_meta
// (OCI source URL) for each unique image:tag so the changelog fetcher has
// a GitHub URL to work with. Containers that used to be running but are
// no longer in Docker's list are deleted so the dashboard shows live state
// only — redeploys (Force Update on Unraid) would otherwise leave stale
// rows under the same image with different container_ids forever.
func (p *Poller) discoverContainers(ctx context.Context) error {
	if p.Docker == nil {
		return nil
	}
	list, err := p.Docker.ListRunning(ctx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	seen := map[string]bool{} // image:tag, so we inspect each only once per cycle

	for _, c := range list {
		image, tag := splitImageTag(c.ImageRef)

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
		`, c.ID, c.Name, image, tag, c.ImageID, c.ComposeProject, c.ComposeService, now, now)
		if err != nil {
			p.Logger.Warn("upsert container", "id", c.ID, "err", err)
			continue
		}

		// Refresh image_meta once per discovery per unique image:tag.
		key := image + ":" + tag
		if seen[key] {
			continue
		}
		seen[key] = true
		p.refreshImageMeta(ctx, image, tag, c.ImageID)
	}

	// Sweep containers that weren't seen this cycle. We reach this line
	// only after a successful ListRunning — a socket hiccup returns
	// early above, so an empty list here genuinely means "no containers
	// running" (user stopped their whole stack), and the sweep should
	// run.
	res, err := p.DB.ExecContext(ctx,
		`DELETE FROM containers WHERE last_seen_at < ?`, now)
	if err != nil {
		p.Logger.Warn("sweep stale containers", "err", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		p.Logger.Info("swept stale containers", "count", n)
	}
	return nil
}

// refreshImageMeta inspects the local image for its OCI labels. We need
// org.opencontainers.image.source (GitHub URL) for the changelog fetcher.
// Also records whether the image is local-only (built from a Dockerfile,
// never pulled from a registry) so the upstream loop can skip it.
// Best-effort — if inspect fails we log and move on.
func (p *Poller) refreshImageMeta(ctx context.Context, image, tag, imageID string) {
	img, err := p.Docker.InspectImage(ctx, imageID)
	if err != nil {
		p.Logger.Debug("inspect image failed", "image", image, "tag", tag, "err", err)
		return
	}
	sourceURL := img.Labels["org.opencontainers.image.source"]
	now := time.Now().Unix()
	_, err = p.DB.ExecContext(ctx, `
		INSERT INTO image_meta (image, tag, source_url, inspected_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(image, tag) DO UPDATE SET
		    source_url = excluded.source_url,
		    inspected_at = excluded.inspected_at
	`, image, tag, sourceURL, now)
	if err != nil {
		p.Logger.Warn("upsert image_meta", "image", image, "tag", tag, "err", err)
	}

	// Empty RepoDigests means this image was built locally (docker build /
	// compose build) and never pulled from a registry. Record it so the
	// upstream loop skips it — otherwise we hit Docker Hub for
	// "<compose-project>-<service>:latest" and pollute the error state.
	if len(img.RepoDigests) == 0 {
		_, err := p.DB.ExecContext(ctx, `
			INSERT INTO local_images (image, tag, detected_at) VALUES (?, ?, ?)
			ON CONFLICT(image, tag) DO UPDATE SET detected_at = excluded.detected_at
		`, image, tag, now)
		if err != nil {
			p.Logger.Warn("upsert local_images", "image", image, "tag", tag, "err", err)
		}
	} else {
		// Image has a registry digest — make sure it isn't stuck in the
		// local-only set from a previous observation.
		_, _ = p.DB.ExecContext(ctx,
			`DELETE FROM local_images WHERE image=? AND tag=?`, image, tag)
	}
}

// --- loop 2: upstream version polling --------------------------------------

func (p *Poller) upstreamLoop(ctx context.Context) {
	// Run once ~30s after start (give discovery a moment), then every cadence
	// — or immediately whenever someone hits "Force check" in the UI.
	//
	// We use time.NewTimer (not time.After) so that a trigger-fire can Stop()
	// the pending cadence timer. Otherwise each click leaks a 6h timer until
	// its natural expiry.
	startTimer := time.NewTimer(30 * time.Second)
	select {
	case <-ctx.Done():
		startTimer.Stop()
		return
	case <-startTimer.C:
	case <-p.triggerCheck:
		startTimer.Stop()
	}

	for {
		p.checkUpstream(ctx)

		cadenceHours := db.SettingGetInt(ctx, p.DB, db.KeyPollCadenceHours, 6)
		if cadenceHours < 1 {
			cadenceHours = 6
		}
		cadenceTimer := time.NewTimer(time.Duration(cadenceHours) * time.Hour)
		select {
		case <-ctx.Done():
			cadenceTimer.Stop()
			return
		case <-cadenceTimer.C:
		case <-p.triggerCheck:
			// User asked for it — stop the pending cadence timer so it
			// doesn't linger in the runtime's timer heap for hours.
			cadenceTimer.Stop()
		}
	}
}

// checkUpstream iterates every unique (image, tag) currently running, calls
// the registry adapter, writes upstream_versions rows, and fires
// notifications / fetches changelogs when a newly-observed digest differs
// from what's running.
func (p *Poller) checkUpstream(ctx context.Context) {
	if p.Registry == nil {
		return
	}

	rows, err := p.DB.QueryContext(ctx, `
		SELECT DISTINCT c.image, c.tag
		FROM containers c
		WHERE c.ignored = 0
		  AND NOT EXISTS (
		      SELECT 1 FROM local_images l
		      WHERE l.image = c.image AND l.tag = c.tag
		  )`)
	if err != nil {
		p.Logger.Warn("upstream list", "err", err)
		return
	}
	var pairs []imageTag
	for rows.Next() {
		var it imageTag
		if err := rows.Scan(&it.image, &it.tag); err == nil {
			pairs = append(pairs, it)
		}
	}
	rows.Close()

	ghToken, _ := db.SettingGet(ctx, p.DB, db.KeyGitHubToken)
	fetcher := changelog.NewFetcher(ghToken)
	notifier := p.buildNotifier(ctx)

	for _, it := range pairs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		p.checkOneUpstream(ctx, it.image, it.tag, fetcher, notifier)
	}
}

type imageTag struct{ image, tag string }

// checkOneUpstream resolves the latest digest for image:tag, records it if
// new, and — if it differs from the currently-running digest — fetches a
// changelog and fires a notification.
func (p *Poller) checkOneUpstream(ctx context.Context, image, tag string, fetcher *changelog.Fetcher, notifier *notify.Client) {
	ref := image + ":" + tag
	adapter := adapterNameFor(ref)
	info, err := p.Registry.LatestDigest(ctx, ref)
	if err != nil {
		if rl, isRL := registry.IsRateLimited(err); isRL {
			until := time.Now().Add(rl.RetryAfter).Unix()
			// Store the raw condition only — the web layer supplies the
			// human remediation hint so there's a single source of truth.
			p.recordRegistryState(ctx, adapter, until, "rate limited (HTTP 429)")
			p.Logger.Warn("registry rate limited", "ref", ref, "retry_after", rl.RetryAfter)
			return
		}
		p.recordRegistryState(ctx, adapter, 0, err.Error())
		p.Logger.Warn("registry check", "ref", ref, "err", err)
		return
	}
	// Success — clear any previous rate-limit/error state for this adapter.
	p.clearRegistryState(ctx, adapter)
	if info == nil || info.Digest == "" {
		return
	}
	now := time.Now().Unix()

	// Has this digest been seen before for image:tag? If yes, just bump checked_at.
	var firstSeen int64
	err = p.DB.QueryRowContext(ctx,
		`SELECT first_seen_at FROM upstream_versions WHERE image=? AND tag=? AND digest=?`,
		image, tag, info.Digest).Scan(&firstSeen)
	isNew := err == sql.ErrNoRows
	if isNew {
		_, err = p.DB.ExecContext(ctx, `
			INSERT INTO upstream_versions (image, tag, digest, first_seen_at, checked_at)
			VALUES (?, ?, ?, ?, ?)`, image, tag, info.Digest, now, now)
		if err != nil {
			p.Logger.Warn("insert upstream_versions", "err", err)
			return
		}
	} else {
		_, _ = p.DB.ExecContext(ctx,
			`UPDATE upstream_versions SET checked_at=? WHERE image=? AND tag=? AND digest=?`,
			now, image, tag, info.Digest)
	}

	if !isNew {
		return
	}
	// New upstream digest. Does it differ from any currently running container
	// using image:tag? (Some rows may have null digest — Docker didn't give one.)
	var running int
	_ = p.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM containers WHERE image=? AND tag=? AND ignored=0
		  AND (current_digest IS NULL OR current_digest != ?)`,
		image, tag, info.Digest).Scan(&running)
	if running == 0 {
		return // we already run this digest
	}

	// There's at least one running container on an older digest — fetch a
	// changelog and fire a notification.
	p.fetchChangelog(ctx, image, tag, fetcher)
	if notifier != nil && notifier.Enabled() {
		short := shortDigest(info.Digest)
		title := "PatchPulse: update available for " + image + ":" + tag
		body := image + ":" + tag + "\nNew digest: " + short + "\nSource: " + info.Source
		if err := notifier.Send(ctx, notify.LevelInfo, title, body); err != nil {
			p.Logger.Warn("apprise notify", "err", err)
		}
	}
}

// fetchChangelog tries to get release notes for image:tag from GitHub. Stored
// even if empty so we don't try again until the tag moves.
func (p *Poller) fetchChangelog(ctx context.Context, image, tag string, fetcher *changelog.Fetcher) {
	var sourceURL string
	_ = p.DB.QueryRowContext(ctx,
		`SELECT COALESCE(source_url, '') FROM image_meta WHERE image=? AND tag=?`,
		image, tag).Scan(&sourceURL)
	if sourceURL == "" {
		return
	}
	res, err := fetcher.Fetch(ctx, sourceURL, tag)
	if err != nil || res == nil {
		p.Logger.Debug("changelog fetch", "image", image, "tag", tag, "err", err)
		return
	}
	now := time.Now().Unix()
	_, err = p.DB.ExecContext(ctx, `
		INSERT INTO changelogs (image, tag, source, markdown, fetched_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(image, tag) DO UPDATE SET
		    source = excluded.source,
		    markdown = excluded.markdown,
		    fetched_at = excluded.fetched_at
	`, image, tag, res.Source, res.ContentHTML, now)
	if err != nil {
		p.Logger.Warn("upsert changelog", "image", image, "tag", tag, "err", err)
	}
}

// --- loop 3: CVE scan ------------------------------------------------------

func (p *Poller) cveLoop(ctx context.Context) {
	if p.Scanner == nil {
		p.Logger.Info("cve scanner disabled (grype not found at startup)")
		return
	}
	// Run initial sweep ~60s after start.
	select {
	case <-ctx.Done():
		return
	case <-time.After(60 * time.Second):
	}
	p.scanDirty(ctx)
	tick := time.NewTicker(15 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.scanDirty(ctx)
		}
	}
}

// scanDirty runs Grype on any container whose current_digest has no cached
// row in cve_results. Respects ctx between scans so we can stop mid-sweep.
func (p *Poller) scanDirty(ctx context.Context) {
	rows, err := p.DB.QueryContext(ctx, `
		SELECT DISTINCT c.image, c.tag, c.current_digest
		FROM containers c
		LEFT JOIN cve_results cv ON cv.image_digest = c.current_digest
		WHERE c.ignored = 0
		  AND c.current_digest IS NOT NULL AND c.current_digest != ''
		  AND cv.image_digest IS NULL
	`)
	if err != nil {
		p.Logger.Warn("cve list", "err", err)
		return
	}
	type target struct{ image, tag, digest string }
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.image, &t.tag, &t.digest); err == nil {
			targets = append(targets, t)
		}
	}
	rows.Close()

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		ref := t.image + ":" + t.tag
		res, err := p.Scanner.Scan(ctx, ref)
		if err != nil {
			p.Logger.Warn("grype scan", "ref", ref, "err", err)
			continue
		}
		now := time.Now().Unix()
		_, err = p.DB.ExecContext(ctx, `
			INSERT INTO cve_results (image_digest, raw_json, scanned_at)
			VALUES (?, ?, ?)
			ON CONFLICT(image_digest) DO UPDATE SET
			    raw_json = excluded.raw_json,
			    scanned_at = excluded.scanned_at
		`, t.digest, res.RawJSON, now)
		if err != nil {
			p.Logger.Warn("store cve_results", "digest", t.digest, "err", err)
		}
	}
}

// --- helpers ---------------------------------------------------------------

// buildNotifier creates an Apprise client from current settings.
// Returns nil if apprise isn't installed or no URLs are configured.
func (p *Poller) buildNotifier(ctx context.Context) *notify.Client {
	var urls []string
	_ = db.SettingGetJSON(ctx, p.DB, db.KeyAppriseURLs, &urls)
	if len(urls) == 0 {
		return nil
	}
	c, err := notify.New("", urls)
	if err != nil {
		p.Logger.Debug("apprise disabled", "err", err)
		return nil
	}
	return c
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// adapterNameFor returns the registry adapter name we'd use for this image
// ref. Mirrors the logic in registry.For but without requiring a Registry
// instance — used for error reporting before we know who's to blame.
func adapterNameFor(imageRef string) string {
	switch {
	case strings.HasPrefix(imageRef, "ghcr.io/"):
		return "ghcr"
	case strings.HasPrefix(imageRef, "quay.io/"):
		return "quay"
	default:
		return "dockerhub"
	}
}

// recordRegistryState writes a rate-limit window and/or last-error row for
// the given adapter. until=0 means "no rate limit, just an error".
func (p *Poller) recordRegistryState(ctx context.Context, adapter string, until int64, errMsg string) {
	now := time.Now().Unix()
	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO registry_state (adapter, rate_limited_until, last_error, last_error_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(adapter) DO UPDATE SET
		    rate_limited_until = excluded.rate_limited_until,
		    last_error         = excluded.last_error,
		    last_error_at      = excluded.last_error_at
	`, adapter, until, errMsg, now)
	if err != nil {
		p.Logger.Warn("persist registry_state", "adapter", adapter, "err", err)
	}
}

// clearRegistryState wipes the rate-limit window + error after a successful
// call — so the dashboard banner disappears automatically.
func (p *Poller) clearRegistryState(ctx context.Context, adapter string) {
	_, _ = p.DB.ExecContext(ctx, `
		UPDATE registry_state SET rate_limited_until=0, last_error=NULL, last_error_at=0
		 WHERE adapter = ? AND (rate_limited_until != 0 OR last_error IS NOT NULL)
	`, adapter)
}

// splitImageTag splits e.g. "nginx:1.25.0" into ("nginx", "1.25.0").
// If no tag is present, defaults to "latest".
func splitImageTag(ref string) (string, string) {
	if at := strings.Index(ref, "@"); at > 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	tagIdx := strings.LastIndex(ref, ":")
	if tagIdx == -1 || tagIdx < slash {
		return ref, "latest"
	}
	return ref[:tagIdx], ref[tagIdx+1:]
}
