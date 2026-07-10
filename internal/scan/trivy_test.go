package scan

import (
	"context"
	"testing"
)

const trivyFixture = `{
  "Results": [
    {
      "Target": "requirements.txt",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1111",
          "PkgName": "requests",
          "InstalledVersion": "2.19.0",
          "FixedVersion": "2.20.0",
          "Severity": "CRITICAL",
          "Title": "requests SSRF",
          "DataSource": {"ID": "nvd", "Name": "NVD"},
          "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L"}},
          "PkgIdentifier": {"PURL": "pkg:pypi/requests@2.19.0"}
        },
        {
          "VulnerabilityID": "GHSA-aaaa-bbbb-cccc",
          "PkgName": "urllib3",
          "InstalledVersion": "1.24.0",
          "FixedVersion": "",
          "Severity": "MEDIUM",
          "Title": "urllib3 issue",
          "PkgIdentifier": {"PURL": "pkg:pypi/urllib3@1.24.0"}
        }
      ]
    }
  ]
}`

func TestParseTrivy(t *testing.T) {
	res, err := parseTrivy([]byte(trivyFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(res.Matches))
	}

	m0 := res.Matches[0]
	if m0.Package.PURL != "pkg:pypi/requests@2.19.0" || m0.Package.Name != "requests" {
		t.Errorf("pkg = %+v", m0.Package)
	}
	if m0.Vuln.SourceID != "CVE-2023-1111" || m0.Vuln.Source != "nvd" {
		t.Errorf("vuln id/source = %q/%q", m0.Vuln.SourceID, m0.Vuln.Source)
	}
	if m0.Vuln.Severity != "HIGH" { // CRITICAL folds to HIGH
		t.Errorf("severity = %q, want HIGH", m0.Vuln.Severity)
	}
	if m0.Vuln.CVSSVector != "CVSS:3.1/AV:N/AC:L" {
		t.Errorf("cvss = %q", m0.Vuln.CVSSVector)
	}
	if m0.FixedVersion != "2.20.0" {
		t.Errorf("fixed = %q", m0.FixedVersion)
	}

	m1 := res.Matches[1]
	if m1.Vuln.Source != "ghsa" || m1.Vuln.Severity != "MEDIUM" {
		t.Errorf("match1 source/sev = %q/%q", m1.Vuln.Source, m1.Vuln.Severity)
	}
}

func TestParseTrivy_Empty(t *testing.T) {
	res, err := parseTrivy(nil)
	if err != nil || len(res.Matches) != 0 {
		t.Fatalf("empty parse = %+v, %v", res, err)
	}
}

func TestTrivy_ScanTreeRequiresWorktree(t *testing.T) {
	tr := &Trivy{runFn: func(context.Context, string) ([]byte, error) { return []byte(trivyFixture), nil }}
	if _, err := tr.ScanTree(context.Background(), ScanScope{}); err == nil {
		t.Fatal("expected error for empty worktree scope")
	}
	res, err := tr.ScanTree(context.Background(), ScanScope{Worktree: "/tmp/x"})
	if err != nil || len(res.Matches) != 2 {
		t.Fatalf("ScanTree = %+v, %v", res, err)
	}
}
