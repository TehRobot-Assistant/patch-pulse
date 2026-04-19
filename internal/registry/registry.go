// Package registry provides shared types and the registry router.
//
// Each image reference is routed to the appropriate adapter
// (Docker Hub, GHCR, Quay) based on its host prefix.
package registry

import (
	"context"
	"strings"
)

// DigestInfo holds the result of checking a registry for the latest digest.
type DigestInfo struct {
	// Digest is the manifest-list (index) digest for multi-arch images,
	// or the single-manifest digest for single-arch images.
	Digest string
	// Tag is the resolved tag.
	Tag string
	// Source is the registry that provided this info.
	Source string
}

// Adapter is the interface each registry driver must implement.
type Adapter interface {
	// LatestDigest fetches the digest for the given image ref (repo:tag).
	// It MUST honour context cancellation and apply 429 backoff internally.
	LatestDigest(ctx context.Context, imageRef string) (*DigestInfo, error)
	// Name returns the adapter identifier for logging.
	Name() string
}

// Registry routes image refs to the right adapter.
type Registry struct {
	adapters []Adapter
}

// New returns a Registry with the provided adapters registered.
func New(adapters ...Adapter) *Registry {
	return &Registry{adapters: adapters}
}

// For returns the adapter that handles the given image ref.
// Falls back to DockerHub for bare image names.
func (r *Registry) For(imageRef string) Adapter {
	host := hostOf(imageRef)
	for _, a := range r.adapters {
		switch a.Name() {
		case "dockerhub":
			if host == "" || host == "docker.io" || host == "registry-1.docker.io" {
				return a
			}
		case "ghcr":
			if host == "ghcr.io" {
				return a
			}
		case "quay":
			if host == "quay.io" {
				return a
			}
		}
	}
	// Default to first adapter (DockerHub).
	if len(r.adapters) > 0 {
		return r.adapters[0]
	}
	return nil
}

// LatestDigest resolves the appropriate adapter and fetches the latest digest.
func (r *Registry) LatestDigest(ctx context.Context, imageRef string) (*DigestInfo, error) {
	adapter := r.For(imageRef)
	if adapter == nil {
		return nil, nil
	}
	return adapter.LatestDigest(ctx, imageRef)
}

// hostOf extracts the hostname portion of an image reference.
// "nginx:latest"           → ""
// "ghcr.io/owner/img:tag"  → "ghcr.io"
// "quay.io/org/img"        → "quay.io"
func hostOf(imageRef string) string {
	parts := strings.SplitN(imageRef, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	// A host contains a dot or a colon (port), otherwise it's a Docker Hub namespace.
	h := parts[0]
	if strings.ContainsAny(h, ".:") {
		return h
	}
	return ""
}

// NormaliseRef converts a bare image ref to its canonical form.
// "nginx" → "library/nginx"
// "nginx:latest" → "library/nginx:latest"
// "myuser/myapp" → "myuser/myapp"
func NormaliseRef(imageRef string) (repo, tag string) {
	ref := imageRef
	// Strip host if present.
	if h := hostOf(ref); h != "" {
		ref = strings.TrimPrefix(ref, h+"/")
	}
	// Split tag.
	parts := strings.SplitN(ref, ":", 2)
	repo = parts[0]
	tag = "latest"
	if len(parts) == 2 && parts[1] != "" {
		tag = parts[1]
	}
	// Bare names are Docker Hub "library" images.
	if !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return repo, tag
}
