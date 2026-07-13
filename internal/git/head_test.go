package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// makeBareRepoWithBranches builds a real bare mirror whose HEAD points at the
// first branch, with a distinct commit on each named branch. Returns the bare path.
func makeBareRepoWithBranches(t *testing.T, branches ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	run(work, "init", "-q", "-b", branches[0], ".")
	for i, b := range branches {
		if i > 0 {
			run(work, "checkout", "-q", "-b", b)
		}
		f := filepath.Join(work, b+".txt")
		if err := os.WriteFile(f, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
		run(work, "add", "-A")
		run(work, "commit", "-q", "-m", b)
	}
	run(work, "checkout", "-q", branches[0]) // leave HEAD on the first branch

	bare := filepath.Join(base, "r.git")
	if out, err := exec.Command("git", "clone", "-q", "--bare", work, bare).CombinedOutput(); err != nil {
		t.Fatalf("git clone --bare: %v\n%s", err, out)
	}
	return bare
}

func TestEnsureServableHead(t *testing.T) {
	ctx := context.Background()

	t.Run("repoints off a hidden default onto a clean branch", func(t *testing.T) {
		repo := makeBareRepoWithBranches(t, "main", "feature")
		if got := headTarget(ctx, repo); got != "refs/heads/main" {
			t.Fatalf("precondition: HEAD = %q, want refs/heads/main", got)
		}
		if err := EnsureServableHead(ctx, repo, []string{"refs/heads/main"}); err != nil {
			t.Fatal(err)
		}
		if got := headTarget(ctx, repo); got != "refs/heads/feature" {
			t.Fatalf("HEAD = %q, want refs/heads/feature (main is quarantined)", got)
		}
	})

	t.Run("orphans HEAD when every branch is hidden", func(t *testing.T) {
		repo := makeBareRepoWithBranches(t, "main", "master")
		if err := EnsureServableHead(ctx, repo, []string{"refs/heads/main", "refs/heads/master"}); err != nil {
			t.Fatal(err)
		}
		if got := headTarget(ctx, repo); got != quarantinedHeadRef {
			t.Fatalf("HEAD = %q, want the unborn quarantine ref", got)
		}
		// The orphaned HEAD resolves to nothing → upload-pack advertises no tip.
		if out, _ := exec.Command("git", "--git-dir", repo, "rev-parse", "-q", "--verify", "HEAD").Output(); len(out) != 0 {
			t.Fatalf("orphaned HEAD still resolves to %q", out)
		}
	})

	t.Run("leaves a clean HEAD untouched", func(t *testing.T) {
		repo := makeBareRepoWithBranches(t, "main", "feature")
		if err := EnsureServableHead(ctx, repo, []string{"refs/heads/feature"}); err != nil {
			t.Fatal(err)
		}
		if got := headTarget(ctx, repo); got != "refs/heads/main" {
			t.Fatalf("HEAD = %q, want refs/heads/main (unchanged)", got)
		}
	})

	t.Run("self-heals HEAD back onto an un-quarantined branch", func(t *testing.T) {
		repo := makeBareRepoWithBranches(t, "main", "master")
		// Quarantine everything → orphaned.
		if err := EnsureServableHead(ctx, repo, []string{"refs/heads/main", "refs/heads/master"}); err != nil {
			t.Fatal(err)
		}
		// main is un-quarantined → HEAD must come back to a real branch (prefers main).
		if err := EnsureServableHead(ctx, repo, []string{"refs/heads/master"}); err != nil {
			t.Fatal(err)
		}
		if got := headTarget(ctx, repo); got != "refs/heads/main" {
			t.Fatalf("HEAD = %q, want refs/heads/main after un-quarantine", got)
		}
	})
}
