// Package cve wraps the grype subprocess for image CVE scanning.
//
// Grype is invoked as an external binary with an arg-slice (no shell
// interpolation). Results are parsed from Grype's JSON output and cached
// in SQLite. The scan is on-demand and idempotent for a given digest.
package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Scanner wraps the grype binary.
type Scanner struct {
	binary string
}

// NewScanner returns a Scanner. binary is the path to grype; if empty,
// it is looked up in $PATH.
func NewScanner(binary string) (*Scanner, error) {
	if binary == "" {
		binary = "grype"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("grype not found (tried %q): %w — install from https://github.com/anchore/grype", binary, err)
	}
	return &Scanner{binary: path}, nil
}

// ScanResult holds parsed Grype output for an image.
type ScanResult struct {
	ScannedAt time.Time
	CVECount  int
	Critical  int
	High      int
	Medium    int
	RawJSON   string
}

// grypeOutput is the top-level structure from `grype -o json`.
type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID         string   `json:"id"`
		Severity   string   `json:"severity"`
		DataSource string   `json:"dataSource"`
		URLs       []string `json:"urls"`
		Fix        struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifact"`
}

// Scan runs grype against the given image ref and returns parsed results.
// The image ref should be the full ref including tag or digest.
// Respects context cancellation for long-running scans.
func (s *Scanner) Scan(ctx context.Context, imageRef string) (*ScanResult, error) {
	// Use arg slice — never interpolate into shell strings.
	cmd := exec.CommandContext(ctx, s.binary,
		imageRef,
		"--output", "json",
		"--quiet",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("grype scan %s: %w: %s", imageRef, err, stderr.String())
	}

	raw := stdout.String()
	var out grypeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("grype parse output: %w", err)
	}

	result := &ScanResult{
		ScannedAt: time.Now(),
		CVECount:  len(out.Matches),
		RawJSON:   raw,
	}
	for _, m := range out.Matches {
		switch m.Vulnerability.Severity {
		case "Critical":
			result.Critical++
		case "High":
			result.High++
		case "Medium":
			result.Medium++
		}
	}
	return result, nil
}

// CVE is a single vulnerability entry from Grype output.
type CVE struct {
	ID             string
	Severity       string
	PackageName    string
	PackageVersion string
	PackageType    string
	FixedVersion   string // first fix version if grype knows one, "" otherwise
	FixState       string // "fixed" | "not-fixed" | "wont-fix" | "unknown" | ""
	URL            string // canonical URL (prefers dataSource, falls back to first URLs entry)
}

// ParseCVEs extracts individual CVE entries from raw Grype JSON.
func ParseCVEs(rawJSON string) ([]CVE, error) {
	var out grypeOutput
	if err := json.Unmarshal([]byte(rawJSON), &out); err != nil {
		return nil, err
	}
	cves := make([]CVE, 0, len(out.Matches))
	for _, m := range out.Matches {
		var fixed string
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixed = m.Vulnerability.Fix.Versions[0]
		}
		url := m.Vulnerability.DataSource
		if url == "" && len(m.Vulnerability.URLs) > 0 {
			url = m.Vulnerability.URLs[0]
		}
		cves = append(cves, CVE{
			ID:             m.Vulnerability.ID,
			Severity:       m.Vulnerability.Severity,
			PackageName:    m.Artifact.Name,
			PackageVersion: m.Artifact.Version,
			PackageType:    m.Artifact.Type,
			FixedVersion:   fixed,
			FixState:       m.Vulnerability.Fix.State,
			URL:            url,
		})
	}
	return cves, nil
}
