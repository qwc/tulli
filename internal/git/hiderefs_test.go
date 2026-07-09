package git

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// makeBareRepo creates a real bare mirror on disk (via git) for the reconcile test.
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

func getHidden(t *testing.T, repoPath string) []string {
	t.Helper()
	out, err := exec.Command("git", "config", "--file", repoPath+"/config", "--get-all", "uploadpack.hideRefs").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil // key absent
		}
		t.Fatalf("git config --get-all: %v", err)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			got = append(got, l)
		}
	}
	return got
}

func TestSetHiddenRefs(t *testing.T) {
	repo := makeBareRepo(t)
	ctx := context.Background()

	// Set two refs.
	if err := SetHiddenRefs(ctx, repo, []string{"refs/heads/evil", "refs/tags/bad"}); err != nil {
		t.Fatal(err)
	}
	if got := getHidden(t, repo); len(got) != 2 || got[0] != "refs/heads/evil" || got[1] != "refs/tags/bad" {
		t.Fatalf("hidden = %v, want the two refs", got)
	}

	// Idempotent + replaces (not accumulates): reconcile to a different single ref.
	if err := SetHiddenRefs(ctx, repo, []string{"refs/heads/only"}); err != nil {
		t.Fatal(err)
	}
	if got := getHidden(t, repo); len(got) != 1 || got[0] != "refs/heads/only" {
		t.Fatalf("after re-reconcile hidden = %v, want [refs/heads/only] (no accumulation)", got)
	}

	// Empty slice clears the block (self-heal on un-quarantine).
	if err := SetHiddenRefs(ctx, repo, nil); err != nil {
		t.Fatal(err)
	}
	if got := getHidden(t, repo); got != nil {
		t.Fatalf("after clear hidden = %v, want none", got)
	}

	// Clearing an already-empty set is a no-op success (--unset-all exit 5).
	if err := SetHiddenRefs(ctx, repo, nil); err != nil {
		t.Fatalf("clearing an empty set should succeed: %v", err)
	}
}

func TestSetHiddenRefs_NotBareRepo(t *testing.T) {
	if err := SetHiddenRefs(context.Background(), t.TempDir(), []string{"refs/heads/x"}); err == nil {
		t.Fatal("want error for a non-bare-repo path")
	}
}
