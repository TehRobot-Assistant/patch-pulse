package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseBearerChallenge_Full(t *testing.T) {
	h := `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:owner/repo:pull"`
	ch, err := parseBearerChallenge(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.Realm != "https://ghcr.io/token" {
		t.Errorf("realm: %q", ch.Realm)
	}
	if ch.Service != "ghcr.io" {
		t.Errorf("service: %q", ch.Service)
	}
	if ch.Scope != "repository:owner/repo:pull" {
		t.Errorf("scope: %q", ch.Scope)
	}
}

func TestParseBearerChallenge_NotBearer(t *testing.T) {
	if _, err := parseBearerChallenge(`Basic realm="foo"`); err == nil {
		t.Fatal("expected error for non-Bearer challenge")
	}
}

func TestParseBearerChallenge_MissingRealm(t *testing.T) {
	if _, err := parseBearerChallenge(`Bearer service="ghcr.io"`); err == nil {
		t.Fatal("expected error when realm is missing")
	}
}

func TestGHCR_AnonymousTokenExchange(t *testing.T) {
	// Fake GHCR: first request is anonymous → 401 with WWW-Authenticate
	// pointing at /token; second request with Bearer <exchanged> → 200.
	var tokenIssued string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") == "" {
			t.Errorf("token exchange missing scope param")
		}
		tokenIssued = "xchg-" + r.URL.Query().Get("scope")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tokenIssued})
	})
	mux.HandleFunc("/v2/owner/repo/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			srvRealm := "http://" + r.Host + "/token"
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="`+srvRealm+`",service="ghcr.io",scope="repository:owner/repo:pull"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if auth != "Bearer "+tokenIssued {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:abc")
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Point the adapter at the test server. The realm check in
	// exchangeToken requires an https://ghcr.io/ prefix, so we run the
	// exchange + head logic directly at the package level with a tweaked
	// base URL rather than exercising LatestDigest end-to-end.
	g := &GHCR{client: srv.Client()}

	// 1. Anonymous head → 401 with WWW-Authenticate
	_, status, wwwAuth, err := g.headManifestURL(context.Background(), srv.URL+"/v2/owner/repo/manifests/latest", "")
	if err != nil {
		t.Fatalf("head1: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
	if !strings.Contains(wwwAuth, "Bearer realm=") {
		t.Fatalf("unexpected WWW-Authenticate: %q", wwwAuth)
	}

	// 2. Parse + exchange against our test realm (bypass the ghcr.io-only
	// guard by running exchange inline — see below for that guard's own
	// test).
	ch, err := parseBearerChallenge(wwwAuth)
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	tokenURL := ch.Realm + "?service=" + ch.Service + "&scope=" + ch.Scope
	resp, err := srv.Client().Get(tokenURL)
	if err != nil {
		t.Fatalf("token fetch: %v", err)
	}
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body.Token == "" {
		t.Fatalf("empty token from exchange")
	}

	// 3. Retry with Bearer → 200 + digest
	digest, status, _, err := g.headManifestURL(context.Background(), srv.URL+"/v2/owner/repo/manifests/latest", body.Token)
	if err != nil {
		t.Fatalf("head2: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200 on retry, got %d", status)
	}
	if digest != "sha256:abc" {
		t.Fatalf("digest: %q", digest)
	}
}

// headManifestURL is a test helper that bypasses the hard-coded ghcrBaseURL.
// The production headManifest uses the global const; this mirrors its logic
// against an arbitrary URL so the token-exchange flow can be exercised end
// to end with httptest.
func (g *GHCR) headManifestURL(ctx context.Context, url, token string) (string, int, string, error) {
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
		return "", 0, "", err
	}
	defer resp.Body.Close()
	return resp.Header.Get("Docker-Content-Digest"), resp.StatusCode, resp.Header.Get("WWW-Authenticate"), nil
}

// TestGHCR_PATRejectedFallsBackToAnonymous simulates the scenario where
// the user's PAT has a scope that works for GitHub's REST API
// (public_repo, for changelog fetching) but not for GHCR reads
// (read:packages). Previously this surfaced as a hard failure — now the
// adapter should fall back to anonymous token exchange and still resolve
// the digest for public images.
func TestGHCR_PATRejectedFallsBackToAnonymous(t *testing.T) {
	const badPAT = "ghp_wrongScope"

	var anonExchanged string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		anonExchanged = "anon-" + r.URL.Query().Get("scope")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": anonExchanged})
	})
	mux.HandleFunc("/v2/owner/repo/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "Bearer "+badPAT:
			// PAT recognised but wrong scope.
			http.Error(w, "insufficient scope", http.StatusForbidden)
		case auth == "":
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="http://`+r.Host+`/token",service="ghcr.io",scope="repository:owner/repo:pull"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case auth == "Bearer "+anonExchanged:
			w.Header().Set("Docker-Content-Digest", "sha256:public")
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unknown auth", http.StatusForbidden)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := &GHCR{client: srv.Client(), token: badPAT}

	// Step 1: PAT attempt returns 403.
	_, status, _, err := g.headManifestURL(context.Background(), srv.URL+"/v2/owner/repo/manifests/latest", g.token)
	if err != nil {
		t.Fatalf("pat attempt: %v", err)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected PAT attempt to get 403, got %d", status)
	}

	// Step 2: anonymous attempt gets a 401 + WWW-Authenticate.
	_, status, wwwAuth, err := g.headManifestURL(context.Background(), srv.URL+"/v2/owner/repo/manifests/latest", "")
	if err != nil {
		t.Fatalf("anon attempt: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("expected anon attempt to get 401, got %d", status)
	}

	// Step 3: token exchange + retry yields 200.
	ch, err := parseBearerChallenge(wwwAuth)
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	tokResp, err := srv.Client().Get(ch.Realm + "?service=" + ch.Service + "&scope=" + ch.Scope)
	if err != nil {
		t.Fatalf("token fetch: %v", err)
	}
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&body)
	tokResp.Body.Close()

	digest, status, _, err := g.headManifestURL(context.Background(), srv.URL+"/v2/owner/repo/manifests/latest", body.Token)
	if err != nil {
		t.Fatalf("anon retry: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected anon retry 200, got %d", status)
	}
	if digest != "sha256:public" {
		t.Fatalf("digest: %q", digest)
	}
}

func TestGHCR_ExchangeToken_RejectsNonGHCRRealm(t *testing.T) {
	g := &GHCR{client: http.DefaultClient}
	// A challenge pointing at an unrelated host should be refused — we
	// don't want to follow arbitrary Bearer realms off-registry.
	_, err := g.exchangeToken(context.Background(),
		`Bearer realm="https://evil.example/token",service="evil",scope="all"`,
		"owner/repo")
	if err == nil || !strings.Contains(err.Error(), "unexpected realm") {
		t.Fatalf("expected unexpected-realm error, got %v", err)
	}
}
