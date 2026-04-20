// Package changelog fetches and sanitises release notes using a fallback chain:
//
//  1. GitHub Releases API (most images have org.opencontainers.image.source)
//  2. CHANGELOG.md from the repo's default branch
//  3. Commit log between old and new tags (last resort)
//
// All fetched content is sanitised through bluemonday before storage.
package changelog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	goldrenderer "github.com/yuin/goldmark/renderer/html"

	hlsecweb "github.com/trstudios/patch-pulse/internal/secweb"
)

const (
	githubAPIBase = "https://api.github.com"
	maxBodyBytes  = 1 << 20 // 1 MiB for changelog content
)

// Fetcher fetches release notes for a given image.
type Fetcher struct {
	client *http.Client
	token  string // GitHub PAT, optional
}

// Result is the fetched changelog content.
type Result struct {
	Source      string // "github_release" | "changelog_md" | "commit_log" | "none"
	ContentHTML string // sanitised HTML, empty if not found
}

// NewFetcher returns a Fetcher. token may be empty (unauthenticated = 60 req/hr).
func NewFetcher(token string) *Fetcher {
	return &Fetcher{
		client: &http.Client{Timeout: 20 * time.Second},
		token:  token,
	}
}

// Fetch attempts to retrieve changelog content for the given sourceURL (OCI source label)
// and tag. Returns an empty Result with Source="none" if nothing is found.
func (f *Fetcher) Fetch(ctx context.Context, sourceURL, tag string) (*Result, error) {
	owner, repo, ok := parseGitHubURL(sourceURL)
	if !ok {
		return &Result{Source: "none"}, nil
	}

	// 1. Try GitHub Releases.
	if r, err := f.fetchGitHubRelease(ctx, owner, repo, tag); err == nil {
		return r, nil
	}

	// 2. Try CHANGELOG.md from default branch.
	if r, err := f.fetchChangelogMD(ctx, owner, repo); err == nil {
		return r, nil
	}

	// 3. Commit log as last resort.
	if r, err := f.fetchCommitLog(ctx, owner, repo, tag); err == nil {
		return r, nil
	}

	return &Result{Source: "none"}, nil
}

// fetchGitHubRelease fetches release notes from the GitHub Releases API.
func (f *Fetcher) fetchGitHubRelease(ctx context.Context, owner, repo, tag string) (*Result, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", githubAPIBase, owner, repo, tag)
	body, err := f.get(ctx, url)
	if err != nil {
		// Also try without 'v' prefix or with it.
		alt := tag
		if strings.HasPrefix(tag, "v") {
			alt = tag[1:]
		} else {
			alt = "v" + tag
		}
		url2 := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", githubAPIBase, owner, repo, alt)
		body, err = f.get(ctx, url2)
		if err != nil {
			return nil, err
		}
	}

	var release struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, err
	}
	if release.Body == "" {
		return nil, fmt.Errorf("empty release body")
	}

	html := markdownToSafeHTML(release.Body)
	return &Result{Source: "github_release", ContentHTML: html}, nil
}

// fetchChangelogMD downloads the CHANGELOG.md from the repo's default branch.
func (f *Fetcher) fetchChangelogMD(ctx context.Context, owner, repo string) (*Result, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/HEAD/CHANGELOG.md", owner, repo)
	body, err := f.get(ctx, url)
	if err != nil {
		return nil, err
	}
	html := markdownToSafeHTML(string(body))
	return &Result{Source: "changelog_md", ContentHTML: html}, nil
}

// fetchCommitLog returns recent commits as a simple HTML list.
func (f *Fetcher) fetchCommitLog(ctx context.Context, owner, repo, tag string) (*Result, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=20", githubAPIBase, owner, repo)
	body, err := f.get(ctx, url)
	if err != nil {
		return nil, err
	}

	var commits []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString("<ul>")
	for _, c := range commits {
		msg := strings.SplitN(c.Commit.Message, "\n", 2)[0]
		fmt.Fprintf(&sb, "<li><code>%s</code> %s</li>", c.SHA[:7], htmlEscape(msg))
	}
	sb.WriteString("</ul>")
	html := hlsecweb.SanitiseHTML(sb.String())
	return &Result{Source: "commit_log", ContentHTML: html}, nil
}

func (f *Fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	limited := io.LimitReader(resp.Body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBodyBytes {
		return nil, hlsecweb.ErrResponseTooLarge
	}
	return data, nil
}

// parseGitHubURL extracts owner/repo from a GitHub URL.
// Handles: https://github.com/owner/repo and https://github.com/owner/repo.git
func parseGitHubURL(sourceURL string) (owner, repo string, ok bool) {
	sourceURL = strings.TrimSuffix(sourceURL, ".git")
	const prefix = "https://github.com/"
	if !strings.HasPrefix(sourceURL, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(sourceURL, prefix)
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// mdRenderer is the shared goldmark parser/renderer. GitHub Flavored
// Markdown (GFM) enables tables, strikethrough, linkify, task lists —
// everything a typical release notes document uses.
var mdRenderer = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(
		goldrenderer.WithHardWraps(),
		// Intentionally NOT using WithUnsafe — we sanitise through
		// bluemonday afterwards so any raw-HTML injection in the markdown
		// would get filtered, but stopping it here earlier is cheap
		// defence-in-depth.
	),
)

// markdownToSafeHTML renders GFM markdown to sanitised HTML. Flow:
//
//  1. goldmark parses the markdown and emits HTML with GFM features
//     (headings, links, lists, tables, code blocks, strikethrough).
//  2. bluemonday (via secweb.SanitiseHTML) strips anything dangerous so
//     even a malicious release-notes body can't run JS in the panel.
func markdownToSafeHTML(md string) string {
	var buf bytes.Buffer
	if err := mdRenderer.Convert([]byte(md), &buf); err != nil {
		// Fallback: render as escaped plain text so the user still sees
		// something if the parser trips on weird input.
		return hlsecweb.SanitiseHTML("<pre>" + htmlEscape(md) + "</pre>")
	}
	return hlsecweb.SanitiseHTML(buf.String())
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
