package scan

import (
	"context"
	"testing"

	"codeberg.org/qwc/tulli/internal/verdict"
)

// A representative gitleaks JSON report (the fields we consume).
const gitleaksJSON = `[
  {
    "Description": "AWS Access Key",
    "StartLine": 3,
    "EndLine": 3,
    "File": "config/prod.yml",
    "Commit": "deadbeefcafe0000000000000000000000000000",
    "RuleID": "aws-access-token",
    "Fingerprint": "deadbeef:config/prod.yml:aws-access-token:3"
  }
]`

func TestParseGitleaks(t *testing.T) {
	res, err := parseGitleaks([]byte(gitleaksJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Scanner != "gitleaks" || f.Severity != verdict.SeverityHigh {
		t.Errorf("scanner/severity = %q/%q, want gitleaks/HIGH", f.Scanner, f.Severity)
	}
	if f.RuleID != "aws-access-token" || f.Commit != "deadbeefcafe0000000000000000000000000000" {
		t.Errorf("rule/commit = %q/%q", f.RuleID, f.Commit)
	}
	if f.Fingerprint == "" || f.FilePath != "config/prod.yml" || f.Line != 3 {
		t.Errorf("fingerprint/file/line = %q/%q/%d", f.Fingerprint, f.FilePath, f.Line)
	}
}

func TestParseGitleaks_EmptyIsClean(t *testing.T) {
	for _, in := range [][]byte{nil, []byte(""), []byte("[]")} {
		res, err := parseGitleaks(in)
		if err != nil || len(res.Findings) != 0 {
			t.Errorf("parseGitleaks(%q) = %+v, %v; want no findings", in, res, err)
		}
	}
}

func TestGitleaks_ScanUsesInjectedRunner(t *testing.T) {
	g := &Gitleaks{runFn: func(_ context.Context, sc ScanScope) ([]byte, error) {
		if sc.RepoPath != "/m/x.git" {
			t.Errorf("scope repo = %q", sc.RepoPath)
		}
		return []byte(gitleaksJSON), nil
	}}
	res, err := g.Scan(context.Background(), ScanScope{RepoPath: "/m/x.git"})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("scan = %+v, %v", res, err)
	}
	if g.Name() != "gitleaks" || g.Descriptor().Lane != Fast {
		t.Errorf("descriptor: name=%q lane=%v", g.Name(), g.Descriptor().Lane)
	}
}
