// Package docker provides a minimal Docker socket client for container discovery.
//
// We use the Docker Engine HTTP API directly over a Unix socket rather than
// importing the full Docker SDK, keeping the dependency footprint small.
package dockercli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client talks to the Docker Engine API over a Unix socket.
type Client struct {
	hc         *http.Client
	socketPath string
}

// NewClient returns a Docker client using the given socket path.
func NewClient(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		hc:         &http.Client{Transport: transport, Timeout: 15 * time.Second},
		socketPath: socketPath,
	}
}

// Container is a discovered running container.
type Container struct {
	ID             string
	Name           string
	ImageRef       string // image:tag as configured
	ImageID        string // full image ID / digest from Docker
	Labels         map[string]string
	ComposeProject string
	ComposeService string
}

// apiContainer is the JSON shape from GET /containers/json.
type apiContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
}

// ListRunning returns all currently running containers.
func (c *Client) ListRunning(ctx context.Context) ([]Container, error) {
	resp, err := c.hc.Get("http://docker/containers/json?filters=%7B%22status%22%3A%5B%22running%22%5D%7D")
	if err != nil {
		return nil, fmt.Errorf("docker list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker list: unexpected status %d", resp.StatusCode)
	}

	var raw []apiContainer
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("docker list decode: %w", err)
	}

	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		name := ""
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		labels := r.Labels
		if labels == nil {
			labels = make(map[string]string)
		}
		c := Container{
			ID:             shortID(r.ID),
			Name:           name,
			ImageRef:       r.Image,
			ImageID:        r.ImageID,
			Labels:         labels,
			ComposeProject: labels["com.docker.compose.project"],
			ComposeService: labels["com.docker.compose.service"],
		}
		out = append(out, c)
	}
	return out, nil
}

// apiImage is used when inspecting an image for its digest.
type apiImage struct {
	ID      string            `json:"Id"`
	RepoDigests []string      `json:"RepoDigests"`
	Labels  map[string]string `json:"Labels"` // Config.Labels
}

// InspectImage returns the image inspect result.
func (c *Client) InspectImage(ctx context.Context, imageID string) (*apiImage, error) {
	resp, err := c.hc.Get("http://docker/images/" + imageID + "/json")
	if err != nil {
		return nil, fmt.Errorf("docker image inspect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker image inspect: status %d", resp.StatusCode)
	}
	var img apiImage
	if err := json.NewDecoder(resp.Body).Decode(&img); err != nil {
		return nil, fmt.Errorf("docker image inspect decode: %w", err)
	}
	return &img, nil
}

// ParseIgnoreLabel returns true if the container has patchpulse.ignore=true.
func ParseIgnoreLabel(labels map[string]string) bool {
	return strings.ToLower(labels["patchpulse.ignore"]) == "true"
}

// ParseNotifyOnlyLabel returns true if the container has patchpulse.notify_only=true.
func ParseNotifyOnlyLabel(labels map[string]string) bool {
	return strings.ToLower(labels["patchpulse.notify_only"]) == "true"
}

// SourceLabel returns the OCI source label (org.opencontainers.image.source) if present.
func SourceLabel(labels map[string]string) string {
	return labels["org.opencontainers.image.source"]
}

// shortID returns the first 12 chars of a Docker container ID.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
