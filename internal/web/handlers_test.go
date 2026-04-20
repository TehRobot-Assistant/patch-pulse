package web

import (
	"strings"
	"testing"
)

func TestRemediationFor(t *testing.T) {
	cases := []struct {
		name        string
		adapter     string
		rawErr      string
		rateLimited bool
		mustContain string
		mustNotHave string
	}{
		{
			name:        "dockerhub transient EOF must not claim rate-limit",
			adapter:     "dockerhub",
			rawErr:      "dockerhub auth library/foo:latest: unexpected EOF",
			mustContain: "transient network",
			mustNotHave: "100 per 6 hours",
		},
		{
			name:        "dockerhub 429 reads as rate-limit",
			adapter:     "dockerhub",
			rawErr:      "rate limited (HTTP 429)",
			rateLimited: true,
			mustContain: "100 per 6 hours",
		},
		{
			name:        "ghcr 401 reads as auth and points at settings UI label",
			adapter:     "ghcr",
			rawErr:      "ghcr: authentication required for ghcr.io/owner/img:latest",
			mustContain: "Settings → GitHub → Personal Access Token",
		},
		{
			name:        "ghcr private image (post-exchange 403)",
			adapter:     "ghcr",
			rawErr:      "ghcr: private image ghcr.io/owner/img — add a GitHub PAT in Settings",
			mustContain: "Personal Access Token",
		},
		{
			name:        "ghcr rate-limit mentions PAT as escape hatch",
			adapter:     "ghcr",
			rawErr:      "rate limited (HTTP 429)",
			rateLimited: true,
			mustContain: "GitHub PAT",
		},
		{
			name:        "not-found suggests ignoring local image",
			adapter:     "dockerhub",
			rawErr:      "dockerhub: image foo:latest not found",
			mustContain: "deleted upstream, renamed, or tagged locally",
		},
		{
			name:        "unknown error falls through to generic",
			adapter:     "dockerhub",
			rawErr:      "completely unexpected weirdness",
			mustContain: "Retries resume automatically",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.ToLower(remediationFor(tc.adapter, tc.rawErr, tc.rateLimited))
			if tc.mustContain != "" && !strings.Contains(got, strings.ToLower(tc.mustContain)) {
				t.Errorf("remediation missing %q:\ngot: %s", tc.mustContain, got)
			}
			if tc.mustNotHave != "" && strings.Contains(got, strings.ToLower(tc.mustNotHave)) {
				t.Errorf("remediation should not contain %q:\ngot: %s", tc.mustNotHave, got)
			}
		})
	}
}
