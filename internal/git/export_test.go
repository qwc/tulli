package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// makeBareRepoWithFile builds a bare mirror containing one commit that adds
// path=content on the default branch, and returns the bare repo path.
func makeBareRepoWithFile(t *testing.T, path, content string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	work := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, path), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")

	bare := filepath.Join(t.TempDir(), "m.git")
	if out, err := exec.Command("git", "clone", "-q", "--bare", work, bare).CombinedOutput(); err != nil {
		t.Fatalf("clone --bare: %v\n%s", err, out)
	}
	return bare
}

func TestDefaultBranchAndExportTree(t *testing.T) {
	bare := makeBareRepoWithFile(t, "hello.txt", "hi there\n")
	ctx := context.Background()

	ref, tip, err := DefaultBranch(ctx, bare)
	if err != nil {
		t.Fatal(err)
	}
	if ref != "refs/heads/main" {
		t.Errorf("DefaultBranch ref = %q, want refs/heads/main", ref)
	}
	if len(tip) != 40 {
		t.Errorf("tip = %q, want a 40-char sha", tip)
	}

	dest := t.TempDir()
	if err := ExportTree(ctx, bare, tip, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil {
		t.Fatalf("exported tree missing hello.txt: %v", err)
	}
	if string(got) != "hi there\n" {
		t.Errorf("exported content = %q, want %q", got, "hi there\n")
	}
	// The export must be tree-only: no .git directory.
	if _, err := os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Error("export should not contain a .git dir")
	}
}
