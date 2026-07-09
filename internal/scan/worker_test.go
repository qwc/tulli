package scan

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/store"
	"codeberg.org/qwc/tulli/internal/verdict"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// stubScanner returns a fixed finding set regardless of scope.
type stubScanner struct{ findings []verdict.Finding }

func (stubScanner) Name() string           { return "gitleaks" }
func (stubScanner) Descriptor() Descriptor { return Descriptor{Lane: Fast} }
func (s stubScanner) Scan(context.Context, ScanScope) (ScanResult, error) {
	return ScanResult{Findings: s.findings}, nil
}

type recRec struct{ repoID int64 }

type recReconciler struct{ calls []recRec }

func (r *recReconciler) ReconcileRepo(_ context.Context, repoID int64, _ string) error {
	r.calls = append(r.calls, recRec{repoID})
	return nil
}

// The worker attributes a HIGH secret to the refs containing its commit, stores
// the findings, recomputes the verdict (QUARANTINED), and triggers reconcile.
func TestWorker_ScanQuarantinesAffectedRef(t *testing.T) {
	st := store.NewMem()
	rec := &recReconciler{}
	attr := func(_ context.Context, _, commit string) ([]string, error) {
		if commit != "C1" {
			t.Errorf("attributor got commit %q", commit)
		}
		return []string{"refs/heads/evil"}, nil
	}
	scanner := stubScanner{findings: []verdict.Finding{
		{Scanner: "gitleaks", Severity: verdict.SeverityHigh, Commit: "C1", Fingerprint: "fp1"},
	}}
	w := NewWorker(scanner, st, attr, rec, discardLogger())

	if err := w.process(context.Background(), core.ScanRequest{RepoID: 5, RepoPath: "/m/x.git"}); err != nil {
		t.Fatal(err)
	}

	// The affected ref is now quarantined (resolver reports it hidden).
	v, _ := st.ResolveVerdict(context.Background(), 5)
	if len(v.HiddenRefs) != 1 || v.HiddenRefs[0] != "refs/heads/evil" {
		t.Fatalf("hidden refs = %v, want [refs/heads/evil]", v.HiddenRefs)
	}
	if len(rec.calls) != 1 || rec.calls[0].repoID != 5 {
		t.Fatalf("reconcile calls = %+v, want one for repo 5", rec.calls)
	}
}

// A clean scan writes a repo-wide CLEAN baseline and hides nothing.
func TestWorker_CleanScanBaseline(t *testing.T) {
	st := store.NewMem()
	rec := &recReconciler{}
	w := NewWorker(stubScanner{}, st, nil, rec, discardLogger())

	if err := w.process(context.Background(), core.ScanRequest{RepoID: 9, RepoPath: "/m/x.git"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := st.CurrentDecision(context.Background(), 9, ""); d != verdict.DecisionClean {
		t.Errorf("repo-wide decision = %q, want CLEAN", d)
	}
	v, _ := st.ResolveVerdict(context.Background(), 9)
	if v.RepoBlocked || len(v.HiddenRefs) != 0 {
		t.Errorf("clean scan should block nothing; got %+v", v)
	}
}

// Enqueue must never block the caller even when the queue is full.
func TestWorker_EnqueueNeverBlocks(t *testing.T) {
	w := NewWorker(stubScanner{}, store.NewMem(), nil, nil, discardLogger())
	// Do not Run the worker, so nothing drains the queue; fill past capacity.
	for i := 0; i < cap(w.jobs)+10; i++ {
		w.Enqueue(core.ScanRequest{RepoID: int64(i)})
	}
	// Reaching here without deadlock is the assertion.
}
