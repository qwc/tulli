package mirror

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/notify"
	"codeberg.org/qwc/tulli/internal/store"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// captureNotifier records delivered notices.
type captureNotifier struct{ notices []notify.Notice }

func (c *captureNotifier) Deliver(_ context.Context, n notify.Notice) error {
	c.notices = append(c.notices, n)
	return nil
}

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

// makeBareRepoWithBranches builds a bare mirror with a commit on each branch and
// HEAD on the first, so reconcile's HEAD handling can be exercised.
func makeBareRepoWithBranches(t *testing.T, branches ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = work, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	run("init", "-q", "-b", branches[0], ".")
	for i, b := range branches {
		if i > 0 {
			run("checkout", "-q", "-b", b)
		}
		if err := os.WriteFile(filepath.Join(work, b+".txt"), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
		run("add", "-A")
		run("commit", "-q", "-m", b)
	}
	run("checkout", "-q", branches[0])
	bare := filepath.Join(base, "r.git")
	if out, err := exec.Command("git", "clone", "-q", "--bare", work, bare).CombinedOutput(); err != nil {
		t.Fatalf("git clone --bare: %v\n%s", err, out)
	}
	return bare
}

func headOf(t *testing.T, repo string) string {
	t.Helper()
	out, _ := exec.Command("git", "--git-dir", repo, "symbolic-ref", "-q", "HEAD").Output()
	return strings.TrimSpace(string(out))
}

// Regression: quarantining a branch must also move HEAD off it. hideRefs does not
// cover the HEAD pseudo-ref, so a hidden default branch would otherwise still be
// served (a client clones it into a detached HEAD, bypassing the ref-hide).
func TestReconcileRepo_HeadLeavesQuarantine(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	r := NewReconciler(st, discardLogger())

	// main tainted, feature clean → HEAD must move to feature.
	repo := makeBareRepoWithBranches(t, "main", "feature")
	id, _ := st.UpsertRepo(ctx, "https://h/o/r", repo)
	st.SetVerdict(id, "refs/heads/main", verdict.DecisionQuarantined, "secret")
	if err := r.ReconcileRepo(ctx, id, repo); err != nil {
		t.Fatal(err)
	}
	if got := headOf(t, repo); got != "refs/heads/feature" {
		t.Fatalf("HEAD = %q, want refs/heads/feature (main quarantined)", got)
	}

	// Every branch tainted → HEAD orphaned, nothing servable.
	repo2 := makeBareRepoWithBranches(t, "main", "master")
	id2, _ := st.UpsertRepo(ctx, "https://h/o/r2", repo2)
	st.SetVerdict(id2, "refs/heads/main", verdict.DecisionQuarantined, "secret")
	st.SetVerdict(id2, "refs/heads/master", verdict.DecisionQuarantined, "secret")
	if err := r.ReconcileRepo(ctx, id2, repo2); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command("git", "--git-dir", repo2, "rev-parse", "-q", "--verify", "HEAD").Output(); len(out) != 0 {
		t.Fatalf("fully-quarantined repo still resolves HEAD to %q — would leak on clone", strings.TrimSpace(string(out)))
	}
}

// A newly-quarantined ref notifies whoever pulled the repo, exactly once — the
// notifications table makes a repeated reconcile idempotent (spec §6d).
func TestReconcile_NotifiesOncePerQuarantine(t *testing.T) {
	repo := makeBareRepo(t)
	st := store.NewMem()
	ctx := context.Background()
	id, _ := st.UpsertRepo(ctx, "https://h/o/r", repo)

	// alice pulled the repo (audit trail → notify recipient).
	uid, _ := st.InsertUser(ctx, "alice", "viewer", "human")
	_ = st.InsertAccessEvent(ctx, core.Access{RepoID: id, UserID: uid, Status: 200})

	cap := &captureNotifier{}
	r := NewReconciler(st, discardLogger()).WithNotifier(cap)

	// Quarantine a ref, reconcile → one notice to alice.
	st.SetVerdict(id, "refs/heads/evil", verdict.DecisionQuarantined, "secret")
	if err := r.ReconcileRepo(ctx, id, repo); err != nil {
		t.Fatal(err)
	}
	if len(cap.notices) != 1 {
		t.Fatalf("got %d notices, want 1", len(cap.notices))
	}
	n := cap.notices[0]
	if n.RepoWide || len(n.Refs) != 1 || n.Refs[0] != "refs/heads/evil" {
		t.Fatalf("notice scope = %+v", n)
	}
	if len(n.Recipients) != 1 || n.Recipients[0].Login != "alice" {
		t.Fatalf("recipients = %+v, want [alice]", n.Recipients)
	}

	// Reconcile again (e.g. the periodic sweep) → no second notice.
	if err := r.ReconcileRepo(ctx, id, repo); err != nil {
		t.Fatal(err)
	}
	if len(cap.notices) != 1 {
		t.Fatalf("got %d notices after re-reconcile, want still 1 (idempotent)", len(cap.notices))
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
