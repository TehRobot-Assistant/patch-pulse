package cve

import "testing"

// Realistic Grype JSON sample shape (trimmed) — matches what's stored
// in cve_results.raw_json after a scan.
const sampleGrypeJSON = `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-1234",
        "severity": "High",
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "urls": ["https://example.com/advisory"],
        "fix": {"versions": ["1.2.3"], "state": "fixed"}
      },
      "artifact": {"name": "openssl", "version": "1.2.0", "type": "apk"}
    },
    {
      "vulnerability": {
        "id": "CVE-2024-9999",
        "severity": "Critical",
        "urls": ["https://example.com/only-urls"],
        "fix": {"versions": [], "state": "not-fixed"}
      },
      "artifact": {"name": "libfoo", "version": "0.9", "type": "deb"}
    }
  ]
}`

func TestParseCVEs_RichFields(t *testing.T) {
	cves, err := ParseCVEs(sampleGrypeJSON)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cves) != 2 {
		t.Fatalf("expected 2 CVEs, got %d", len(cves))
	}

	// First match has dataSource + fix version set.
	c0 := cves[0]
	if c0.ID != "CVE-2024-1234" || c0.Severity != "High" {
		t.Errorf("bad id/sev: %+v", c0)
	}
	if c0.PackageName != "openssl" || c0.PackageVersion != "1.2.0" || c0.PackageType != "apk" {
		t.Errorf("bad pkg: %+v", c0)
	}
	if c0.FixedVersion != "1.2.3" || c0.FixState != "fixed" {
		t.Errorf("bad fix: %+v", c0)
	}
	if c0.URL != "https://nvd.nist.gov/vuln/detail/CVE-2024-1234" {
		t.Errorf("expected dataSource URL, got %q", c0.URL)
	}

	// Second match has no dataSource — should fall back to URLs[0].
	c1 := cves[1]
	if c1.URL != "https://example.com/only-urls" {
		t.Errorf("expected URLs[0] fallback, got %q", c1.URL)
	}
	if c1.FixedVersion != "" || c1.FixState != "not-fixed" {
		t.Errorf("bad not-fixed parse: %+v", c1)
	}
}

func TestParseCVEs_Empty(t *testing.T) {
	cves, err := ParseCVEs(`{"matches":[]}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("expected 0, got %d", len(cves))
	}
}

func TestParseCVEs_Malformed(t *testing.T) {
	if _, err := ParseCVEs(`not json`); err == nil {
		t.Error("expected error for malformed input")
	}
}
