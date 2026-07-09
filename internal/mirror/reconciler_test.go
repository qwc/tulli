package mirror

import (
	"context"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/qwc/tulli/internal/store"
	"codeberg.org/qwc/tulli/internal/verdict"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func makeBareRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := filepath.Join(t.TempDir(), "r.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return dir
}

func hiddenRefs(t *testing.T, repoPath string) []string {
	t.Helper()
	out, err := exec.Command("git", "config", "--file", repoPath+"/config", "--get-all", "uploadpack.hideRefs").Output()
	if err != nil {
		return nil // key absent
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			got = append(got, l)
		}
	}
	return got
}

// ReconcileRepo makes the mirror's hideRefs match the store's current verdicts.
func TestReconcileRepo_AppliesAndClearsHideRefs(t *testing.T) {
	repo := makeBareRepo(t)
	st := store.NewMem()
	ctx := context.Background()
	id, _ := st.UpsertRepo(ctx, "https://h/o/r", repo)
	r := NewReconciler(st, discardLogger())

	// Quarantine a ref → reconcile hides it.
	st.SetVerdict(id, "refs/heads/evil", verdict.DecisionQuarantined, "secret")
	if err := r.ReconcileRepo(ctx, id, repo); err != nil {
		t.Fatal(err)
	}
	if got := hiddenRefs(t, repo); len(got) != 1 || got[0] != "refs/heads/evil" {
		t.Fatalf("hidden = %v, want [refs/heads/evil]", got)
	}

	// Un-quarantine (newer CLEAN) → reconcile clears it.
	st.SetVerdict(id, "refs/heads/evil", verdict.DecisionClean, "")
	if err := r.ReconcileRepo(ctx, id, repo); err != nil {
		t.Fatal(err)
	}
	if got := hiddenRefs(t, repo); got != nil {
		t.Fatalf("hidden = %v, want none after un-quarantine", got)
	}
}

// The sweep recomputes verdicts written out of process (an override) and applies
// the result to disk — the path the demo scaffold and future web API use.
func TestSweep_OverrideRecomputesAndClears(t *testing.T) {
	repo := makeBareRepo(t)
	st := store.NewMem()
	ctx := context.Background()
	id, _ := st.UpsertRepo(ctx, "https://h/o/r", repo)

	// A stored HIGH finding on evil, then recompute+reconcile → hidden.
	_ = st.InsertFinding(ctx, 0, id, "refs/heads/evil",
		verdict.Finding{Scanner: "gitleaks", Severity: verdict.SeverityHigh, Fingerprint: "fp1"})
	r := NewReconciler(st, discardLogger())
	if err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hiddenRefs(t, repo); len(got) != 1 {
		t.Fatalf("after finding, hidden = %v, want evil hidden", got)
	}

	// Override the fingerprint (out-of-process write) → next sweep lifts it.
	_ = st.InsertOverride(ctx, id, "refs/heads/evil", "fp1", "false positive", "itsec")
	if err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hiddenRefs(t, repo); got != nil {
		t.Fatalf("after override, hidden = %v, want cleared", got)
	}
}
