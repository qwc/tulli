package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Trivy is the deep-lane SBOM/CVE scanner (spec §8.5–8.6). It scans a
// materialised tree (a worktree exported from a ref tip) and reports each
// vulnerability matched to a package. These findings NEVER gate — they populate
// the vuln tables and the triage queue (§6.6). Every hit is a triage item, so
// severity here is informational, not a block trigger.
type Trivy struct {
	// runFn executes trivy over a worktree and returns its JSON report.
	// Injectable so the parser and worker are tested without the binary.
	runFn func(ctx context.Context, worktree string) ([]byte, error)
}

func NewTrivy() *Trivy { return &Trivy{runFn: runTrivy} }

func (t *Trivy) Name() string { return "trivy" }

func (t *Trivy) Descriptor() Descriptor {
	return Descriptor{Attribution: Component, Lane: Deep, Triggers: []Trigger{OnUpdate, OnTimer, Manual}}
}

func (t *Trivy) ScanTree(ctx context.Context, scope ScanScope) (DeepResult, error) {
	if scope.Worktree == "" {
		return DeepResult{}, fmt.Errorf("trivy: empty worktree scope")
	}
	out, err := t.runFn(ctx, scope.Worktree)
	if err != nil {
		return DeepResult{}, err
	}
	return parseTrivy(out)
}

// trivyReport is the subset of `trivy fs --format json` we consume.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			DataSource       *struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
			} `json:"DataSource"`
			CVSS map[string]struct {
				V3Vector string `json:"V3Vector"`
			} `json:"CVSS"`
			References    []string `json:"References"`
			PkgIdentifier struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivy(data []byte) (DeepResult, error) {
	if len(data) == 0 {
		return DeepResult{}, nil
	}
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return DeepResult{}, fmt.Errorf("parse trivy report: %w", err)
	}
	var out DeepResult
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			purl := v.PkgIdentifier.PURL
			if purl == "" { // fall back to a synthetic purl so components are still keyable
				purl = "pkg:generic/" + v.PkgName + "@" + v.InstalledVersion
			}
			out.Matches = append(out.Matches, Match{
				Package: Package{PURL: purl, Name: v.PkgName, Version: v.InstalledVersion},
				Vuln: Vulnerability{
					Source:     trivySource(v.VulnerabilityID),
					SourceID:   v.VulnerabilityID,
					Kind:       "CVE",
					Severity:   mapTrivySeverity(v.Severity),
					CVSSVector: trivyVector(v.CVSS),
					Summary:    v.Title,
				},
				ToolSeverity: v.Severity,
				FixedVersion: v.FixedVersion,
			})
		}
	}
	return out, nil
}

// mapTrivySeverity folds trivy's five levels into our LOW/MEDIUM/HIGH (§8.6).
func mapTrivySeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL", "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	default: // LOW, UNKNOWN, ""
		return "LOW"
	}
}

// trivySource derives an advisory database key from the vuln id prefix (OSV
// identity, §8.6): GHSA-/RUSTSEC-/etc. keep their prefix; CVE-* come via NVD.
func trivySource(id string) string {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return "ghsa"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "rustsec"
	case strings.HasPrefix(id, "CVE-"):
		return "nvd"
	default:
		if i := strings.IndexByte(id, '-'); i > 0 {
			return strings.ToLower(id[:i])
		}
		return "unknown"
	}
}

// trivyVector picks a CVSS v3 vector from trivy's per-source CVSS map, if any.
func trivyVector(m map[string]struct {
	V3Vector string `json:"V3Vector"`
}) string {
	for _, c := range m {
		if c.V3Vector != "" {
			return c.V3Vector
		}
	}
	return ""
}

// runTrivy is the production runner: an offline (pre-warmed DB) filesystem scan
// for vulnerabilities, emitting JSON to stdout.
func runTrivy(ctx context.Context, worktree string) ([]byte, error) {
	if _, err := exec.LookPath("trivy"); err != nil {
		return nil, fmt.Errorf("trivy not installed: %w", err)
	}
	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--quiet", "--format", "json", "--scanners", "vuln", "--skip-db-update", worktree)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy fs: %w", err)
	}
	return out, nil
}
