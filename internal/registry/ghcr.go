// Package registry — GHCR (GitHub Container Registry) adapter.
package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const ghcrBaseURL = "https://ghcr.io/v2"

// GHCR implements Adapter for GitHub Container Registry.
type GHCR struct {
	client *http.Client
	// token is the GitHub PAT (optional; anonymous pulls work for public images).
	token string
}

// NewGHCR returns a GHCR adapter. token may be empty for public images.
func NewGHCR(token string) *GHCR {
	return &GHCR{
		client: &http.Client{Timeout: 30 * time.Second},
		token:  token,
	}
}

func (g *GHCR) Name() string { return "ghcr" }

// LatestDigest fetches the manifest-list digest for a GHCR image.
func (g *GHCR) LatestDigest(ctx context.Context, imageRef string) (*DigestInfo, error) {
	// Strip ghcr.io/ prefix to get the repo path.
	ref := strings.TrimPrefix(imageRef, "ghcr.io/")
	parts := strings.SplitN(ref, ":", 2)
	repo := parts[0]
	tag := "latest"
	if len(parts) == 2 {
		tag = parts[1]
	}

	url := fmt.Sprintf("%s/%s/manifests/%s", ghcrBaseURL, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghcr head %s: %w", imageRef, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		digest := resp.Header.Get("Docker-Content-Digest")
		if digest == "" {
			return nil, fmt.Errorf("ghcr: no digest header for %s", imageRef)
		}
		return &DigestInfo{Digest: digest, Tag: tag, Source: "ghcr"}, nil
	case http.StatusUnauthorized:
		// Try anonymous token exchange.
		return nil, fmt.Errorf("ghcr: authentication required for %s (set github.token in config)", imageRef)
	case http.StatusTooManyRequests:
		return nil, &ErrRateLimited{RetryAfter: parseRetryAfter(resp)}
	default:
		return nil, fmt.Errorf("ghcr: HEAD %s → HTTP %d", imageRef, resp.StatusCode)
	}
}
