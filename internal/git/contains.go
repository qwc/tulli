package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// RefsContaining returns the branch and tag refs in the bare mirror that reach
// commit (spec §8.1: `git for-each-ref --contains`). This is how a
// commit-attributed finding (gitleaks) is mapped to the ref(s) it quarantines —
// and attributing a secret to every ref that contains its commit is exactly
// right, because the blob is cloneable from all of them (§6.7 reachability).
func RefsContaining(ctx context.Context, repoPath, commit string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "--git-dir", repoPath,
		"for-each-ref", "--contains", commit, "--format=%(refname)",
		"refs/heads/", "refs/tags/")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("for-each-ref --contains %s: %w: %s", commit, err, strings.TrimSpace(stderr.String()))
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	return refs, nil
}
