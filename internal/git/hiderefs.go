package git

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SetHiddenRefs makes the bare mirror at repoPath hide exactly refs from
// upload-pack (spec §6.4). A hidden ref is not advertised, and git refuses a
// `want` for its unadvertised objects, so the ref-level quarantine holds even
// against a client that knows the SHA — airtight when the bad commit stands
// alone (the reachable-from-clean case is Strategy B, deferred §6.5).
//
// tulli owns every bare mirror it creates, so it also owns the whole
// uploadpack.hideRefs multivar: the reconcile is a clear-then-add that makes the
// on-disk set match the argument exactly. It is idempotent and an empty refs
// slice clears the block (self-heal on un-quarantine).
func SetHiddenRefs(ctx context.Context, repoPath string, refs []string) error {
	if !isBareRepo(repoPath) {
		return fmt.Errorf("hideRefs: %s is not a bare mirror", repoPath)
	}
	// Clear our existing entries first. `--unset-all` exits 5 when the key is
	// absent; that is a no-op success for us, not an error.
	if err := gitConfig(ctx, repoPath, "--unset-all", "uploadpack.hideRefs"); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 5 {
			return err
		}
	}
	for _, ref := range refs {
		if err := gitConfig(ctx, repoPath, "--add", "uploadpack.hideRefs", ref); err != nil {
			return err
		}
	}
	return nil
}

func gitConfig(ctx context.Context, repoPath string, args ...string) error {
	full := append([]string{"config", "--file", repoPath + "/config"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return err // preserve exit code (callers inspect it, e.g. 5 = key absent)
		}
		return fmt.Errorf("git config %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
