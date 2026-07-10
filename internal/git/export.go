package git

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DefaultBranch reports the mirror's default branch: its symbolic HEAD ref and
// the commit that ref points at. This is the tree-state target for the Deep lane
// (Trivy) in the prototype — we SBOM/CVE-scan the default branch tip.
func DefaultBranch(ctx context.Context, repoPath string) (ref, tip string, err error) {
	ref, err = runGit(ctx, repoPath, "symbolic-ref", "HEAD")
	if err != nil {
		// Detached or unusual HEAD — fall back to whatever HEAD resolves to.
		ref = "HEAD"
	}
	tip, err = runGit(ctx, repoPath, "rev-parse", "HEAD")
	if err != nil {
		return "", "", err
	}
	return ref, tip, nil
}

// ExportTree materialises the tree at commit-ish rev into destDir (which must
// exist and be empty) via `git archive | tar -x`. A bare mirror has no worktree,
// so tools that need real files (Trivy `fs`) get an ephemeral checkout the caller
// deletes after scanning. No refs, history, or .git — just the tree state.
func ExportTree(ctx context.Context, repoPath, rev, destDir string) error {
	archive := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "archive", "--format=tar", rev)
	untar := exec.CommandContext(ctx, "tar", "-x", "-C", destDir)

	pipe, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	untar.Stdin = pipe

	var aerr, uerr bytes.Buffer
	archive.Stderr, untar.Stderr = &aerr, &uerr
	if err := untar.Start(); err != nil {
		return fmt.Errorf("start tar: %w", err)
	}
	if err := archive.Run(); err != nil {
		_ = untar.Wait()
		return fmt.Errorf("git archive %s: %w: %s", rev, err, strings.TrimSpace(aerr.String()))
	}
	if err := untar.Wait(); err != nil {
		return fmt.Errorf("tar extract: %w: %s", err, strings.TrimSpace(uerr.String()))
	}
	return nil
}

// runGit runs a git subcommand against a bare mirror and returns trimmed stdout.
func runGit(ctx context.Context, repoPath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"--git-dir", repoPath}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// MkTempExport creates a fresh temp dir for an ExportTree target and returns it
// with a cleanup func. Convenience for the Deep worker.
func MkTempExport(prefix string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", prefix)
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}
