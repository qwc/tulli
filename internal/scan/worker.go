package scan

import (
	"context"
	"log/slog"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// Store is what the worker persists through. It is verdict.Store (recompute
// inputs/outputs) plus the raw scan/finding writers. Both internal/store.Mem and
// internal/store/pg satisfy it.
type Store interface {
	verdict.Store
	InsertScan(ctx context.Context, repoID int64, scanner, scopeKind, scopeExpr string) (int64, error)
	InsertFinding(ctx context.Context, scanID, repoID int64, ref string, f verdict.Finding) error
}

// Reconciler applies the recomputed verdicts to the on-disk mirror (hideRefs).
// Implemented by internal/mirror.Reconciler; a narrow seam avoids an import on
// the whole mirror package.
type Reconciler interface {
	ReconcileRepo(ctx context.Context, repoID int64, repoPath string) error
}

// Attributor maps a finding's commit to the refs that reach it (spec §8.1).
// Implemented by internal/git.RefsContaining.
type Attributor func(ctx context.Context, repoPath, commit string) ([]string, error)

// Worker runs scans off the request path (fail-open-once, spec §7). It owns a
// single fast-lane scanner for the prototype (gitleaks); the lane split (§8.4)
// is where a deep-lane pool would be added.
type Worker struct {
	scanner    Scanner
	store      Store
	attribute  Attributor
	reconciler Reconciler
	log        *slog.Logger
	jobs       chan core.ScanRequest
}

func NewWorker(scanner Scanner, store Store, attr Attributor, rec Reconciler, log *slog.Logger) *Worker {
	return &Worker{
		scanner:    scanner,
		store:      store,
		attribute:  attr,
		reconciler: rec,
		log:        log,
		jobs:       make(chan core.ScanRequest, 128),
	}
}

// Enqueue implements core.Enqueuer. Never blocks the request path: a full queue
// spills onto a goroutine rather than stalling the fetch.
func (w *Worker) Enqueue(req core.ScanRequest) {
	select {
	case w.jobs <- req:
	default:
		go func() { w.jobs <- req }()
	}
}

// Run processes the queue until ctx is cancelled. Single worker for the
// prototype; a fast-lane pool is a trivial fan-out here.
func (w *Worker) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-w.jobs:
			if err := w.process(ctx, req); err != nil {
				w.log.Error("scan job failed", "repo_id", req.RepoID, "err", err)
			}
		}
	}
}

// process is the fail-open-once pipeline: scan → attribute findings to refs →
// persist → recompute verdicts → reconcile hideRefs.
func (w *Worker) process(ctx context.Context, req core.ScanRequest) error {
	res, err := w.scanner.Scan(ctx, ScanScope{RepoPath: req.RepoPath, Range: req.Range})
	if err != nil {
		return err
	}

	scanID, err := w.store.InsertScan(ctx, req.RepoID, w.scanner.Name(), "RANGE", req.Range)
	if err != nil {
		return err
	}

	for _, f := range res.Findings {
		if f.Commit == "" {
			continue // unattributable without a commit; skip (gitleaks always has one)
		}
		refs, err := w.attribute(ctx, req.RepoPath, f.Commit)
		if err != nil {
			w.log.Error("attribute finding failed", "commit", f.Commit, "err", err)
			continue
		}
		for _, ref := range refs {
			if err := w.store.InsertFinding(ctx, scanID, req.RepoID, ref, f); err != nil {
				return err
			}
		}
	}

	// Recompute every affected ref (+ a CLEAN baseline if none) then apply.
	if err := verdict.RecomputeRepo(ctx, w.store, req.RepoID); err != nil {
		return err
	}
	if w.reconciler != nil {
		return w.reconciler.ReconcileRepo(ctx, req.RepoID, req.RepoPath)
	}
	return nil
}
