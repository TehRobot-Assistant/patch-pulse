// Package registry — Docker Hub adapter.
//
// Uses Docker Hub's registry API v2 with HEAD-first polling:
//   1. HEAD /v2/<repo>/manifests/<tag> to get the digest header cheaply.
//   2. Only fetch the full manifest if the digest has changed.
//
// 429 handling: exponential backoff with jitter, stored back-off window in the
// caller (poller) via the RateLimitedUntil field in the versions table.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	dockerHubAuthURL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull"
	dockerHubBaseURL = "https://registry-1.docker.io/v2"
)

// DockerHub implements Adapter for Docker Hub.
type DockerHub struct {
	client *http.Client
}

// NewDockerHub returns a DockerHub adapter.
func NewDockerHub() *DockerHub {
	return &DockerHub{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *DockerHub) Name() string { return "dockerhub" }

// LatestDigest fetches the manifest-list digest for an image ref.
// Returns a 429 error wrapped as ErrRateLimited so the caller can back off.
func (d *DockerHub) LatestDigest(ctx context.Context, imageRef string) (*DigestInfo, error) {
	repo, tag := NormaliseRef(imageRef)

	token, err := d.fetchToken(ctx, repo)
	if err != nil {
		return nil, fmt.Errorf("dockerhub auth %s: %w", imageRef, err)
	}

	digest, err := d.headManifest(ctx, repo, tag, token)
	if err != nil {
		return nil, err
	}
	return &DigestInfo{Digest: digest, Tag: tag, Source: "dockerhub"}, nil
}

// fetchToken obtains an anonymous pull token from Docker Hub.
func (d *DockerHub) fetchToken(ctx context.Context, repo string) (string, error) {
	url := fmt.Sprintf(dockerHubAuthURL, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, 4096)
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(limited).Decode(&tok); err != nil {
		return "", err
	}
	return tok.Token, nil
}

// headManifest performs a HEAD request to get the manifest digest.
// Requests both manifest list (multi-arch) and regular manifests.
func (d *DockerHub) headManifest(ctx context.Context, repo, tag, token string) (string, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", dockerHubBaseURL, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// Request manifest list first (multi-arch), then OCI index, then v2 schema.
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))

	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		digest := resp.Header.Get("Docker-Content-Digest")
		if digest == "" {
			return "", fmt.Errorf("dockerhub: no digest header for %s/%s:%s", repo, repo, tag)
		}
		return digest, nil
	case http.StatusTooManyRequests:
		return "", &ErrRateLimited{RetryAfter: parseRetryAfter(resp)}
	case http.StatusNotFound:
		return "", fmt.Errorf("dockerhub: image %s:%s not found", repo, tag)
	default:
		return "", fmt.Errorf("dockerhub: HEAD %s:%s → HTTP %d", repo, tag, resp.StatusCode)
	}
}

// ErrRateLimited is returned when the registry responds with 429.
// The RetryAfter field indicates how long to wait.
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("rate limited by registry; retry after %s", e.RetryAfter)
}

// IsRateLimited reports whether an error is a rate-limit error.
func IsRateLimited(err error) (*ErrRateLimited, bool) {
	if err == nil {
		return nil, false
	}
	// Walk the error chain.
	for err != nil {
		if rl, ok := err.(*ErrRateLimited); ok {
			return rl, true
		}
		// unwrap one level
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
		} else {
			break
		}
	}
	return nil, false
}

func parseRetryAfter(resp *http.Response) time.Duration {
	// Respect Retry-After header if present.
	if v := resp.Header.Get("Retry-After"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			return d
		}
	}
	return 60 * time.Minute // conservative default
}
