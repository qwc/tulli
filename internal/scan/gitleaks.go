package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"codeberg.org/qwc/tulli/internal/verdict"
)

// Gitleaks is the secret scanner (spec §8.1): it walks git history and reports a
// finding per leaked secret, each stamped with the Commit it lives on and a
// stable Fingerprint (used to key overrides, §8.1). Every gitleaks hit is treated
// as HIGH — a leaked credential is deterministic and low-FP (§6.6), so it
// auto-quarantines.
type Gitleaks struct {
	// runFn executes gitleaks over scope and returns its JSON report. Injectable
	// so the parser and worker are tested without the binary (absent in dev).
	runFn func(ctx context.Context, scope ScanScope) ([]byte, error)
}

func NewGitleaks() *Gitleaks { return &Gitleaks{runFn: runGitleaks} }

func (g *Gitleaks) Name() string { return "gitleaks" }

func (g *Gitleaks) Descriptor() Descriptor {
	return Descriptor{Attribution: Commit, Lane: Fast, Triggers: []Trigger{OnUpdate, Manual}}
}

func (g *Gitleaks) Scan(ctx context.Context, scope ScanScope) (ScanResult, error) {
	out, err := g.runFn(ctx, scope)
	if err != nil {
		return ScanResult{}, err
	}
	return parseGitleaks(out)
}

// gitleaksReport is the subset of gitleaks' JSON report we consume.
type gitleaksReport struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
}

func parseGitleaks(data []byte) (ScanResult, error) {
	if len(data) == 0 {
		return ScanResult{}, nil // no report file / empty = no leaks
	}
	var rows []gitleaksReport
	if err := json.Unmarshal(data, &rows); err != nil {
		return ScanResult{}, fmt.Errorf("parse gitleaks report: %w", err)
	}
	res := ScanResult{Findings: make([]verdict.Finding, 0, len(rows))}
	for _, r := range rows {
		res.Findings = append(res.Findings, verdict.Finding{
			Scanner:     "gitleaks",
			Severity:    verdict.SeverityHigh, // every secret is HIGH (§6.6)
			RuleID:      r.RuleID,
			FilePath:    r.File,
			Line:        r.StartLine,
			Commit:      r.Commit,
			Fingerprint: r.Fingerprint,
			Description: r.Description,
		})
	}
	return res, nil
}

// runGitleaks is the production runner. gitleaks exits 1 when it finds leaks
// (expected, not an error); any other non-zero is a real failure. The report is
// written to a temp file and read back.
func runGitleaks(ctx context.Context, scope ScanScope) ([]byte, error) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		return nil, fmt.Errorf("gitleaks not installed: %w", err)
	}
	report, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return nil, err
	}
	report.Close()
	defer os.Remove(report.Name())

	args := []string{"detect", "--source", scope.RepoPath, "--no-banner",
		"--report-format", "json", "--report-path", report.Name()}
	if scope.Range != "" {
		args = append(args, "--log-opts", scope.Range)
	} else {
		args = append(args, "--log-opts", "--all") // whole in-window history (§8.3 floor deferred)
	}
	cmd := exec.CommandContext(ctx, "gitleaks", args...)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 { // 1 = leaks found (fine)
			return nil, fmt.Errorf("gitleaks: %w", err)
		}
	}
	return os.ReadFile(report.Name())
}
