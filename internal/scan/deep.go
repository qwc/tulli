package scan

import (
	"context"
	"log/slog"

	"codeberg.org/qwc/tulli/internal/core"
)

// DeepStore is what the deep worker persists through: a tree scan, then the SBOM
// (components), advisories (vulnerabilities), their join (vuln_matches), and a
// triage item per match. All primitives so the store need not import scan. Both
// internal/store.Mem and internal/store/pg satisfy it.
type DeepStore interface {
	InsertTreeScan(ctx context.Context, repoID int64, scanner, ref, tip string) (int64, error)
	UpsertVulnerability(ctx context.Context, source, sourceID string, aliases []string, kind, severity, cvssVector, summary string) (int64, error)
	UpsertComponent(ctx context.Context, repoID int64, ref, tip, purl string, scanID int64) (int64, error)
	UpsertVulnMatch(ctx context.Context, componentID, vulnID, scanID int64, scanner, toolSeverity, fixedVersion string) (int64, error)
	OpenTriage(ctx context.Context, repoID int64, ref string, matchID int64) error
}

// Exporter materialises a ref tip's tree into destDir (internal/git.ExportTree).
type Exporter func(ctx context.Context, repoPath, rev, destDir string) error

// DefaultBrancher resolves a mirror's default branch ref + tip
// (internal/git.DefaultBranch) — the tree-state target for the deep scan.
type DefaultBrancher func(ctx context.Context, repoPath string) (ref, tip string, err error)

// TempDirer makes a fresh temp export dir and its cleanup (internal/git.MkTempExport).
type TempDirer func(prefix string) (dir string, cleanup func(), err error)

// DeepWorker runs the deep lane (SBOM / CVE) off the request path, entirely
// separate from the fast/secret Worker so a slow external tool can't starve it
// (spec §8.4). Its output lands in the vuln tables and the triage queue — it does
// NOT recompute verdicts or reconcile, because CVEs never gate (§6.6).
type DeepWorker struct {
	scanner DeepScanner
	store   DeepStore
	export  Exporter
	branch  DefaultBrancher
	tempDir TempDirer
	log     *slog.Logger
	jobs    chan core.ScanRequest
}

func NewDeepWorker(scanner DeepScanner, store DeepStore, export Exporter, branch DefaultBrancher, tempDir TempDirer, log *slog.Logger) *DeepWorker {
	return &DeepWorker{
		scanner: scanner, store: store, export: export, branch: branch, tempDir: tempDir,
		log: log, jobs: make(chan core.ScanRequest, 128),
	}
}

// Enqueue implements core.Enqueuer; never blocks the request path.
func (w *DeepWorker) Enqueue(req core.ScanRequest) {
	select {
	case w.jobs <- req:
	default:
		go func() { w.jobs <- req }()
	}
}

func (w *DeepWorker) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-w.jobs:
			if err := w.process(ctx, req); err != nil {
				w.log.Error("deep scan job failed", "repo_id", req.RepoID, "err", err)
			}
		}
	}
}

// process: resolve default branch tip → export its tree → Trivy → persist SBOM +
// advisories + matches → open triage. No verdict/reconcile.
func (w *DeepWorker) process(ctx context.Context, req core.ScanRequest) error {
	ref, tip, err := w.branch(ctx, req.RepoPath)
	if err != nil {
		return err
	}
	dir, cleanup, err := w.tempDir("tulli-deep-")
	if err != nil {
		return err
	}
	defer cleanup()
	if err := w.export(ctx, req.RepoPath, tip, dir); err != nil {
		return err
	}

	res, err := w.scanner.ScanTree(ctx, ScanScope{RepoPath: req.RepoPath, Ref: ref, Tip: tip, Worktree: dir})
	if err != nil {
		return err
	}

	scanID, err := w.store.InsertTreeScan(ctx, req.RepoID, w.scanner.Name(), ref, tip)
	if err != nil {
		return err
	}

	for _, m := range res.Matches {
		vulnID, err := w.store.UpsertVulnerability(ctx, m.Vuln.Source, m.Vuln.SourceID, m.Vuln.Aliases,
			m.Vuln.Kind, m.Vuln.Severity, m.Vuln.CVSSVector, m.Vuln.Summary)
		if err != nil {
			return err
		}
		compID, err := w.store.UpsertComponent(ctx, req.RepoID, ref, tip, m.Package.PURL, scanID)
		if err != nil {
			return err
		}
		matchID, err := w.store.UpsertVulnMatch(ctx, compID, vulnID, scanID, w.scanner.Name(), m.ToolSeverity, m.FixedVersion)
		if err != nil {
			return err
		}
		if err := w.store.OpenTriage(ctx, req.RepoID, ref, matchID); err != nil {
			return err
		}
	}
	w.log.Info("deep scan complete", "repo_id", req.RepoID, "ref", ref, "matches", len(res.Matches))
	return nil
}

// FanOut is a core.Enqueuer that hands each request to several enqueuers — used
// to trigger both the fast (secret) and deep (SBOM/CVE) workers on first fetch.
type FanOut []core.Enqueuer

func (f FanOut) Enqueue(req core.ScanRequest) {
	for _, e := range f {
		if e != nil {
			e.Enqueue(req)
		}
	}
}
