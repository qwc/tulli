package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/qwc/tulli/internal/verdict"
)

// TestGitleaks_ScanBareMirror exercises the *production* runGitleaks path (the
// injected runner is bypassed) against a real bare mirror — the exact shape
// tulli scans (`git clone --mirror`, then `gitleaks detect --source <bare.git>
// --log-opts --all`). This closes the long-standing "gitleaks on a bare mirror
// is unvalidated" gap: `detect` drives `git log`, which works on a bare repo, so
// no `--git-dir`/checkout is needed. Skips when git or gitleaks is absent (the
// binary is not vendored; installed ad hoc in the dev sandbox), mirroring the
// embedded-postgres/real-git integration tests.
func TestGitleaks_ScanBareMirror(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (real gitleaks); skipped under -short")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}

	// A pattern-valid AWS access key that is NOT AWS's well-known documentation
	// example (AKIAIOSFODNN7EXAMPLE), which gitleaks' default ruleset allowlists.
	// The aws-access-token rule matches AKIA[0-9A-Z]{16}. Fixed (not random) so
	// the test is deterministic.
	const awsKey = "AKIAZ7X4QF2NLW8RTV3D"
	bare := buildTaintedBareMirror(t, awsKey)

	// Production runner (no injected runFn) over the bare mirror, full history —
	// empty Range is the worker's full-scan scope (runGitleaks → --log-opts --all).
	res, err := NewGitleaks().Scan(context.Background(), ScanScope{RepoPath: bare})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Scanner != "gitleaks" || f.Severity != verdict.SeverityHigh {
		t.Errorf("scanner/severity = %q/%q, want gitleaks/HIGH", f.Scanner, f.Severity)
	}
	if f.RuleID != "aws-access-token" {
		t.Errorf("rule = %q, want aws-access-token", f.RuleID)
	}
	// The worker keys overrides on the fingerprint and attributes via the commit;
	// both must be populated for the quarantine→override arc to work end to end.
	if f.Fingerprint == "" {
		t.Error("fingerprint is empty (overrides key on it)")
	}
	if f.Commit == "" {
		t.Error("commit is empty (worker attributes findings to reaching refs by commit)")
	}
	if f.FilePath != "src/config.py" {
		t.Errorf("file = %q, want src/config.py", f.FilePath)
	}
}

// TestGitleaks_ScanCleanBareMirror is the negative case: a clean bare mirror
// yields no findings (and gitleaks' exit 0 is not mistaken for an error).
func TestGitleaks_ScanCleanBareMirror(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (real gitleaks); skipped under -short")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
	bare := buildCleanBareMirror(t)
	res, err := NewGitleaks().Scan(context.Background(), ScanScope{RepoPath: bare})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %d, want 0: %+v", len(res.Findings), res.Findings)
	}
}

// buildTaintedBareMirror builds a bare mirror whose tag v1-leak points at a
// commit leaking awsKey in src/config.py (main stays clean) — the demo's
// bare_tainted fixture shape.
func buildTaintedBareMirror(t *testing.T, awsKey string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-C", src,
			"-c", "user.email=demo@tulli", "-c", "user.name=demo"}, args...)
		if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	mustInit(t, src)
	writeFile(t, filepath.Join(src, "README.md"), "clean main\n")
	git("add", "-A")
	git("commit", "-qm", "init")
	git("checkout", "-q", "-b", "leak")
	writeFile(t, filepath.Join(src, "src", "config.py"), "AWS_ACCESS_KEY_ID = \""+awsKey+"\"\n")
	git("add", "-A")
	git("commit", "-qm", "add deploy config")
	git("tag", "v1-leak")
	git("checkout", "-q", "main")
	git("branch", "-D", "leak") // the leaky commit lives only under the tag

	bare := filepath.Join(t.TempDir(), "widget.git")
	if out, err := exec.Command("git", "clone", "-q", "--mirror", src, bare).CombinedOutput(); err != nil {
		t.Fatalf("git clone --mirror: %v\n%s", err, out)
	}
	return bare
}

// buildCleanBareMirror builds a bare mirror with a single clean commit on main.
func buildCleanBareMirror(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	mustInit(t, src)
	writeFile(t, filepath.Join(src, "README.md"), "hello from tulli demo\n")
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-qm", "init"}} {
		full := append([]string{"-C", src,
			"-c", "user.email=demo@tulli", "-c", "user.name=demo"}, args...)
		if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	bare := filepath.Join(t.TempDir(), "clean.git")
	if out, err := exec.Command("git", "clone", "-q", "--mirror", src, bare).CombinedOutput(); err != nil {
		t.Fatalf("git clone --mirror: %v\n%s", err, out)
	}
	return bare
}

func mustInit(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", "-b", "main", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
