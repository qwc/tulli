package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// quarantinedHeadRef is the unborn ref tulli points HEAD at when every branch of
// a mirror is quarantined. It exists nowhere, so upload-pack advertises no HEAD
// and a fully-quarantined repo serves nothing — instead of leaking its default
// branch through the (never-hidden) HEAD pseudo-ref.
const quarantinedHeadRef = "refs/heads/__tulli_quarantined__"

// EnsureServableHead keeps the mirror's HEAD out of the quarantine.
//
// uploadpack.hideRefs hides matching refs, but NOT the HEAD symref: if HEAD still
// points at a hidden branch, git advertises HEAD with its OID, an advertised tip
// is always want-able, and a client clones the quarantined content into a
// detached HEAD — bypassing the ref-hide entirely. So after hiding refs we must
// also move HEAD off any hidden branch: repoint it to a non-hidden branch, or —
// if no clean branch remains — orphan it to an unborn ref so nothing is served.
//
// Idempotent, and self-healing: when a branch is later un-quarantined the next
// reconcile repoints HEAD back onto a real branch.
func EnsureServableHead(ctx context.Context, repoPath string, hidden []string) error {
	hiddenSet := make(map[string]bool, len(hidden))
	for _, r := range hidden {
		hiddenSet[r] = true
	}

	branches, err := listBranches(ctx, repoPath)
	if err != nil {
		return err
	}
	clean := make([]string, 0, len(branches))
	for _, b := range branches {
		if !hiddenSet[b] {
			clean = append(clean, b)
		}
	}

	head := headTarget(ctx, repoPath) // "" if detached/unresolvable
	// HEAD is fine iff it points at an existing, non-hidden branch.
	if head != "" && !hiddenSet[head] && contains(clean, head) {
		return nil
	}

	target := quarantinedHeadRef
	if len(clean) > 0 {
		target = preferredHead(clean)
	}
	if head == target {
		return nil
	}
	return setSymbolicHead(ctx, repoPath, target)
}

// listBranches returns the mirror's local branch refs (refs/heads/*), sorted.
func listBranches(ctx context.Context, repoPath string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "--git-dir", repoPath,
		"for-each-ref", "--format=%(refname)", "refs/heads/")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("for-each-ref refs/heads/: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	return refs, nil
}

// headTarget returns HEAD's symbolic target (e.g. refs/heads/main), or "" if HEAD
// is detached or points nowhere resolvable.
func headTarget(ctx context.Context, repoPath string) string {
	cmd := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "symbolic-ref", "-q", "HEAD")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(stdout.String())
}

func setSymbolicHead(ctx context.Context, repoPath, target string) error {
	cmd := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "symbolic-ref", "HEAD", target)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("symbolic-ref HEAD %s: %w: %s", target, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// preferredHead picks a deterministic default from the clean branches: main, then
// master, else the lexically-first (stable, so reconcile doesn't flap).
func preferredHead(clean []string) string {
	for _, pref := range []string{"refs/heads/main", "refs/heads/master"} {
		if contains(clean, pref) {
			return pref
		}
	}
	sorted := append([]string(nil), clean...)
	sort.Strings(sorted)
	return sorted[0]
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
