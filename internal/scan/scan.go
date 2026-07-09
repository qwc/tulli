// Package scan is the scanning lane (spec §8): the Scanner seam plus the async
// worker that runs a scan, attributes findings to refs, recomputes verdicts, and
// triggers reconcile. Only gitleaks (fast lane, secrets) is implemented in the
// prototype; the Descriptor/ScanScope machinery (§8.4) is general so a Trivy or
// Deep-lane adapter slots in later without touching the core.
package scan

import (
	"context"

	"codeberg.org/qwc/tulli/internal/verdict"
)

// Attribution says what a finding attaches to (spec §8.4/§8.6).
type Attribution int

const (
	Commit    Attribution = iota // gitleaks: a commit in history
	TreeState                    // Trivy: a ref tip's tree
	Component                    // a purl@version (CVE)
)

// Lane separates fast local shell-outs from slow external tools so one can't
// starve the other (spec §8.4). Only Fast is used in the prototype.
type Lane int

const (
	Fast Lane = iota
	Deep
)

// Trigger is when a scanner runs (spec §8.2).
type Trigger int

const (
	OnUpdate Trigger = iota
	OnTimer
	Manual
)

// Descriptor is a scanner's capability profile — how it's driven and what it
// attributes to (spec §8.4).
type Descriptor struct {
	Attribution Attribution
	Lane        Lane
	Triggers    []Trigger
}

// ScanScope is the target of one scan. History scanners use Range; tree-state
// scanners use Ref/Tip; tools needing a checkout use Worktree (spec §8.4).
type ScanScope struct {
	RepoPath string
	Ref      string
	Tip      string
	Range    string
	Worktree string
}

// ScanResult is what a scan produced. Findings carry the scanner's own severity
// mapped into LOW/MEDIUM/HIGH.
type ScanResult struct {
	Findings []verdict.Finding
}

// Scanner is the extension seam (spec §8.4). Adding a scanner is one new file
// plus one line in the registry.
type Scanner interface {
	Name() string
	Descriptor() Descriptor
	Scan(ctx context.Context, scope ScanScope) (ScanResult, error)
}
