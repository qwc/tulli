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

// Scanner is the fast-lane extension seam (spec §8.4): it produces gating
// findings. Adding one is a new file plus a line in the registry.
type Scanner interface {
	Name() string
	Descriptor() Descriptor
	Scan(ctx context.Context, scope ScanScope) (ScanResult, error)
}

// --- Deep lane (spec §8.5–8.7): SBOM + CVE, which NEVER gate. ---

// Vulnerability is one advisory, normalised on OSV identity (source + source_id
// + aliases) and CVSS (spec §8.6). Kind is CVE or MALWARE.
type Vulnerability struct {
	Source     string   // advisory database, e.g. "ghsa", "nvd"
	SourceID   string   // e.g. "CVE-2024-1234", "GHSA-xxxx"
	Aliases    []string // other ids for the same advisory
	Kind       string   // "CVE" | "MALWARE"
	Severity   string   // LOW | MEDIUM | HIGH
	CVSSVector string
	Summary    string
}

// Package is a component present in a scanned tree, identified by PURL (spec
// §8.6). It becomes a row in the `components` table.
type Package struct {
	PURL    string
	Name    string
	Version string
}

// Match is a Vulnerability affecting a Package, as reported by the deep scanner
// (the join Trivy already computed; spec §8.5). It carries the operands so the
// worker can persist SBOM (component) and advisory (vuln) separately.
type Match struct {
	Package      Package
	Vuln         Vulnerability
	ToolSeverity string
	FixedVersion string
}

// DeepResult is what a tree-state (SBOM/CVE) scan produced.
type DeepResult struct {
	Matches []Match
}

// DeepScanner is the deep-lane seam. Its output lands in the vuln tables and the
// triage queue — never the gate. A worktree (materialised tree) is the input,
// because these tools scan files, not history.
type DeepScanner interface {
	Name() string
	Descriptor() Descriptor
	ScanTree(ctx context.Context, scope ScanScope) (DeepResult, error)
}
