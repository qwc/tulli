// Package mirror owns the reconciler (spec §4, IMPLEMENTATION §4): it makes the
// on-disk uploadpack.hideRefs of each bare mirror match the DB's current
// verdicts. The DB is desired state; only this mirror-owning process may write
// the git config, so every intent (scan worker, future web API) flows to disk
// through here. (The refresh scheduler, §8.8, will also live here later.)
package mirror

import (
	"context"
	"log/slog"
	"time"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// Store is what the reconciler reads. It is verdict.Store (so the sweep can
// recompute verdicts from findings+overrides written out of process, e.g. by the
// future web API or the demo scaffold) plus repo enumeration and verdict
// resolution. Both internal/store.Mem and internal/store/pg satisfy it.
type Store interface {
	verdict.Store
	ListRepos(ctx context.Context) ([]core.RepoInfo, error)
	ResolveVerdict(ctx context.Context, repoID int64) (core.Verdict, error)
}

type Reconciler struct {
	store Store
	log   *slog.Logger
}

func NewReconciler(store Store, log *slog.Logger) *Reconciler {
	return &Reconciler{store: store, log: log}
}

// ReconcileRepo applies the repo's current verdicts to its mirror: it hides
// exactly the ref-level QUARANTINED refs (spec §6.4). Called by the scan worker
// after it writes verdicts (event-driven). A repo-wide block needs no hideRefs
// (it is enforced at the gate by the ERR pkt-line), so only HiddenRefs matter.
func (r *Reconciler) ReconcileRepo(ctx context.Context, repoID int64, repoPath string) error {
	v, err := r.store.ResolveVerdict(ctx, repoID)
	if err != nil {
		return err
	}
	return git.SetHiddenRefs(ctx, repoPath, v.HiddenRefs) // empty slice clears
}

// Sweep is the periodic safety pass (+ boot): for every mirror it recomputes
// verdicts from stored findings+overrides — catching writes made out of process,
// which is how the web API (and the stage-4 demo's override scaffold) actuate —
// then reconciles hideRefs. writeIfChanged keeps this idempotent.
func (r *Reconciler) Sweep(ctx context.Context) error {
	repos, err := r.store.ListRepos(ctx)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if err := verdict.RecomputeRepo(ctx, r.store, repo.ID); err != nil {
			r.log.Error("sweep recompute failed", "repo_id", repo.ID, "err", err)
			continue
		}
		if err := r.ReconcileRepo(ctx, repo.ID, repo.MirrorPath); err != nil {
			r.log.Error("sweep reconcile failed", "repo_id", repo.ID, "err", err)
		}
	}
	return nil
}

// Run does a boot sweep, then sweeps every interval until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) {
	if err := r.Sweep(ctx); err != nil {
		r.log.Error("boot reconcile sweep failed", "err", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.Sweep(ctx)
		}
	}
}
