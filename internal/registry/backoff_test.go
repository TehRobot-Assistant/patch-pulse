package registry_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/trstudios/patch-pulse/internal/registry"
)

func TestIsRateLimited(t *testing.T) {
	rl := &registry.ErrRateLimited{RetryAfter: 30 * time.Minute}

	got, ok := registry.IsRateLimited(rl)
	if !ok {
		t.Fatal("expected IsRateLimited to return true for *ErrRateLimited")
	}
	if got.RetryAfter != 30*time.Minute {
		t.Errorf("RetryAfter: want 30m, got %v", got.RetryAfter)
	}
}

func TestIsRateLimited_Wrapped(t *testing.T) {
	rl := &registry.ErrRateLimited{RetryAfter: 10 * time.Minute}
	wrapped := fmt.Errorf("outer: %w", rl)

	_, ok := registry.IsRateLimited(wrapped)
	if !ok {
		t.Fatal("expected IsRateLimited to detect wrapped ErrRateLimited")
	}
}

func TestIsRateLimited_OtherError(t *testing.T) {
	err := fmt.Errorf("some other error")
	_, ok := registry.IsRateLimited(err)
	if ok {
		t.Error("expected IsRateLimited to return false for non-rate-limit error")
	}
}

func TestIsRateLimited_Nil(t *testing.T) {
	_, ok := registry.IsRateLimited(nil)
	if ok {
		t.Error("expected IsRateLimited to return false for nil error")
	}
}

func TestNormaliseRef(t *testing.T) {
	cases := []struct {
		input    string
		wantRepo string
		wantTag  string
	}{
		{"nginx", "library/nginx", "latest"},
		{"nginx:1.25", "library/nginx", "1.25"},
		{"myuser/myapp:v2", "myuser/myapp", "v2"},
		{"myuser/myapp", "myuser/myapp", "latest"},
		{"ghcr.io/owner/img:tag", "owner/img", "tag"},
	}
	for _, tc := range cases {
		repo, tag := registry.NormaliseRef(tc.input)
		if repo != tc.wantRepo || tag != tc.wantTag {
			t.Errorf("NormaliseRef(%q) = (%q, %q), want (%q, %q)",
				tc.input, repo, tag, tc.wantRepo, tc.wantTag)
		}
	}
}

func TestErrRateLimitedMessage(t *testing.T) {
	rl := &registry.ErrRateLimited{RetryAfter: 5 * time.Minute}
	if rl.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
