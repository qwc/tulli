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
	"codeberg.org/qwc/tulli/internal/notify"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// Store is what the reconciler reads. It is verdict.Store (so the sweep can
// recompute verdicts from findings+overrides written out of process, e.g. by the
// future web API or the demo scaffold) plus repo enumeration, verdict resolution,
// and — for notify (§6d) — recipient lookup and idempotent notification
// recording. Both internal/store.Mem and internal/store/pg satisfy it.
type Store interface {
	verdict.Store
	ListRepos(ctx context.Context) ([]core.RepoInfo, error)
	ResolveVerdict(ctx context.Context, repoID int64) (core.Verdict, error)
	RecipientsForRepo(ctx context.Context, repoID int64) ([]core.Recipient, error)
	RecordNotificationForLatestVerdict(ctx context.Context, repoID int64, ref string, recipients []int64, payloadPath string) (bool, error)
}

type Reconciler struct {
	store    Store
	notifier notify.Notifier // nil = notifications disabled
	log      *slog.Logger
}

func NewReconciler(store Store, log *slog.Logger) *Reconciler {
	return &Reconciler{store: store, log: log}
}

// WithNotifier enables quarantine notifications (spec §6d). Returns the
// reconciler for chaining.
func (r *Reconciler) WithNotifier(n notify.Notifier) *Reconciler {
	r.notifier = n
	return r
}

// ReconcileRepo applies the repo's current verdicts to its mirror: it hides
// exactly the ref-level QUARANTINED refs (spec §6.4). Called by the scan worker
// after it writes verdicts (event-driven). A repo-wide block needs no hideRefs
// (it is enforced at the gate by the ERR pkt-line), so only HiddenRefs matter.
// After applying, it notifies whoever pulled a newly-quarantined repo/ref (once
// per verdict; the notifications table makes the periodic sweep idempotent).
func (r *Reconciler) ReconcileRepo(ctx context.Context, repoID int64, repoPath string) error {
	v, err := r.store.ResolveVerdict(ctx, repoID)
	if err != nil {
		return err
	}
	if err := git.SetHiddenRefs(ctx, repoPath, v.HiddenRefs); err != nil { // empty slice clears
		return err
	}
	r.notifyQuarantine(ctx, repoID, repoPath, v)
	return nil
}

// notifyQuarantine records + delivers a notification for each currently-active
// quarantine (repo-wide and per hidden ref) that hasn't been notified yet.
// Best-effort: a notify failure never blocks reconciliation.
func (r *Reconciler) notifyQuarantine(ctx context.Context, repoID int64, repoPath string, v core.Verdict) {
	if r.notifier == nil || (!v.RepoBlocked && len(v.HiddenRefs) == 0) {
		return
	}
	recipients, err := r.store.RecipientsForRepo(ctx, repoID)
	if err != nil {
		r.log.Error("notify: recipient lookup failed", "repo_id", repoID, "err", err)
		return
	}
	ids := make([]int64, len(recipients))
	for i, rc := range recipients {
		ids[i] = rc.UserID
	}

	deliver := func(ref string, repoWide bool, refs []string, reason string) {
		notice := notify.Notice{
			RepoID: repoID, Repo: repoPath, RepoWide: repoWide, Refs: refs,
			Reason: reason, Recipients: recipients,
		}
		inserted, err := r.store.RecordNotificationForLatestVerdict(ctx, repoID, ref, ids, notify.PayloadDescriptor(notice))
		if err != nil {
			r.log.Error("notify: record failed", "repo_id", repoID, "ref", ref, "err", err)
			return
		}
		if !inserted {
			return // already notified for this verdict
		}
		if err := r.notifier.Deliver(ctx, notice); err != nil {
			r.log.Error("notify: deliver failed", "repo_id", repoID, "err", err)
		}
	}

	if v.RepoBlocked {
		deliver("", true, nil, v.Reason)
	}
	for _, ref := range v.HiddenRefs {
		deliver(ref, false, []string{ref}, "ref quarantined")
	}
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
