// Package registry — GHCR (GitHub Container Registry) adapter.
//
// GHCR requires Bearer auth for every read — even public images. Anonymous
// callers must complete a token-exchange dance:
//
//  1. HEAD /v2/<repo>/manifests/<tag>           → 401 + WWW-Authenticate
//  2. GET realm?service=...&scope=...           → {"token": "..."}
//  3. Retry the HEAD with "Authorization: Bearer <token>"
//
// If a user-supplied PAT is configured we skip the exchange and use it
// directly (step 3 only). The PAT is the escape hatch for private images
// and rate-limit headroom; it isn't required for public pulls.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const ghcrBaseURL = "https://ghcr.io/v2"

// GHCR implements Adapter for GitHub Container Registry.
type GHCR struct {
	client *http.Client
	// token is the GitHub PAT (optional; anonymous pulls work for public images
	// via token exchange).
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

// manifestAccept is the tuple of media types we prefer when asking the
// registry for a manifest. Multi-arch first, then single-arch fallbacks.
var manifestAccept = strings.Join([]string{
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
}, ", ")

// LatestDigest fetches the manifest-list digest for a GHCR image.
func (g *GHCR) LatestDigest(ctx context.Context, imageRef string) (*DigestInfo, error) {
	ref := strings.TrimPrefix(imageRef, "ghcr.io/")
	parts := strings.SplitN(ref, ":", 2)
	repo := parts[0]
	tag := "latest"
	if len(parts) == 2 {
		tag = parts[1]
	}

	// First attempt: use PAT if provided, else anonymous.
	digest, status, wwwAuth, err := g.headManifest(ctx, repo, tag, g.token)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		if digest == "" {
			return nil, fmt.Errorf("ghcr: no digest header for %s", imageRef)
		}
		return &DigestInfo{Digest: digest, Tag: tag, Source: "ghcr"}, nil
	case http.StatusUnauthorized:
		// Anonymous path: parse WWW-Authenticate and do the token exchange.
		if g.token != "" {
			// PAT was supplied and still got 401 — don't mask as anonymous.
			return nil, fmt.Errorf("ghcr: authentication failed for %s (check GitHub PAT in Settings)", imageRef)
		}
		exchanged, err := g.exchangeToken(ctx, wwwAuth, repo)
		if err != nil {
			return nil, fmt.Errorf("ghcr token exchange for %s: %w", imageRef, err)
		}
		digest, status, _, err = g.headManifest(ctx, repo, tag, exchanged)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
			if digest == "" {
				return nil, fmt.Errorf("ghcr: no digest header for %s", imageRef)
			}
			return &DigestInfo{Digest: digest, Tag: tag, Source: "ghcr"}, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, fmt.Errorf("ghcr: private image %s — add a GitHub PAT in Settings", imageRef)
		case http.StatusNotFound:
			return nil, fmt.Errorf("ghcr: image %s not found", imageRef)
		case http.StatusTooManyRequests:
			return nil, &ErrRateLimited{RetryAfter: 60 * time.Minute}
		default:
			return nil, fmt.Errorf("ghcr: HEAD %s → HTTP %d", imageRef, status)
		}
	case http.StatusNotFound:
		return nil, fmt.Errorf("ghcr: image %s not found", imageRef)
	case http.StatusTooManyRequests:
		return nil, &ErrRateLimited{RetryAfter: 60 * time.Minute}
	default:
		return nil, fmt.Errorf("ghcr: HEAD %s → HTTP %d", imageRef, status)
	}
}

// headManifest performs a single HEAD request. Returns the digest on 200,
// or the status code (and raw WWW-Authenticate header on 401) on error so
// the caller can decide whether to retry with a fresh token.
func (g *GHCR) headManifest(ctx context.Context, repo, tag, token string) (digest string, status int, wwwAuth string, err error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", ghcrBaseURL, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("Accept", manifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("ghcr head %s: %w", repo, err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("Docker-Content-Digest"), resp.StatusCode, resp.Header.Get("WWW-Authenticate"), nil
}

// exchangeToken follows the WWW-Authenticate Bearer challenge to obtain an
// anonymous pull token. realm must point at ghcr.io/token (we don't honour
// arbitrary hosts to avoid being steered off-registry).
func (g *GHCR) exchangeToken(ctx context.Context, wwwAuth, repo string) (string, error) {
	ch, err := parseBearerChallenge(wwwAuth)
	if err != nil {
		// Fall back to the documented ghcr.io/token endpoint with the
		// expected scope — works in practice even without a challenge.
		ch = bearerChallenge{
			Realm:   "https://ghcr.io/token",
			Service: "ghcr.io",
			Scope:   "repository:" + repo + ":pull",
		}
	}
	if !strings.HasPrefix(ch.Realm, "https://ghcr.io/") {
		return "", fmt.Errorf("unexpected realm %q", ch.Realm)
	}

	// Build the query via url.Values so hostile service/scope values from
	// the WWW-Authenticate header can't inject extra params. Realm is
	// already guarded above to be on ghcr.io.
	q := url.Values{}
	if ch.Service != "" {
		q.Set("service", ch.Service)
	}
	if ch.Scope != "" {
		q.Set("scope", ch.Scope)
	}
	u := ch.Realm
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange HTTP %d", resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	// 32 KiB is generous — current GHCR tokens sit well under 4 KiB, but
	// future payload growth or extra fields (expires_in, issued_at) shouldn't
	// silently truncate and produce a decode error.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32*1024)).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("empty token in response")
}

// bearerChallenge is the parsed WWW-Authenticate Bearer params.
type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

// parseBearerChallenge extracts realm / service / scope from a header like
//
//	Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:owner/repo:pull"
func parseBearerChallenge(h string) (bearerChallenge, error) {
	var ch bearerChallenge
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ch, fmt.Errorf("not a Bearer challenge: %q", h)
	}
	rest := h[len("Bearer "):]
	for _, part := range splitChallengeParams(rest) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), "\"")
		switch strings.ToLower(key) {
		case "realm":
			ch.Realm = val
		case "service":
			ch.Service = val
		case "scope":
			ch.Scope = val
		}
	}
	if ch.Realm == "" {
		return ch, errors.New("missing realm")
	}
	return ch, nil
}

// splitChallengeParams splits on commas that aren't inside quoted strings.
func splitChallengeParams(s string) []string {
	var out []string
	var buf strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			inQuote = !inQuote
			buf.WriteByte(c)
		case ',':
			if inQuote {
				buf.WriteByte(c)
			} else {
				out = append(out, strings.TrimSpace(buf.String()))
				buf.Reset()
			}
		default:
			buf.WriteByte(c)
		}
	}
	if buf.Len() > 0 {
		out = append(out, strings.TrimSpace(buf.String()))
	}
	return out
}
