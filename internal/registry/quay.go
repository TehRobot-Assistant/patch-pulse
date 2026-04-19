// Package registry — Quay.io adapter.
package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const quayBaseURL = "https://quay.io/v2"

// Quay implements Adapter for Quay.io.
type Quay struct {
	client *http.Client
}

// NewQuay returns a Quay adapter.
func NewQuay() *Quay {
	return &Quay{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (q *Quay) Name() string { return "quay" }

// LatestDigest fetches the manifest-list digest for a Quay.io image.
func (q *Quay) LatestDigest(ctx context.Context, imageRef string) (*DigestInfo, error) {
	ref := strings.TrimPrefix(imageRef, "quay.io/")
	parts := strings.SplitN(ref, ":", 2)
	repo := parts[0]
	tag := "latest"
	if len(parts) == 2 {
		tag = parts[1]
	}

	url := fmt.Sprintf("%s/%s/manifests/%s", quayBaseURL, repo, tag)
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

	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quay head %s: %w", imageRef, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		digest := resp.Header.Get("Docker-Content-Digest")
		if digest == "" {
			return nil, fmt.Errorf("quay: no digest header for %s", imageRef)
		}
		return &DigestInfo{Digest: digest, Tag: tag, Source: "quay"}, nil
	case http.StatusTooManyRequests:
		return nil, &ErrRateLimited{RetryAfter: parseRetryAfter(resp)}
	default:
		return nil, fmt.Errorf("quay: HEAD %s → HTTP %d", imageRef, resp.StatusCode)
	}
}
