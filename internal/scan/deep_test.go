package scan

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/store"
)

// fakeDeep is a DeepScanner returning a fixed result, so the worker pipeline is
// tested without trivy or a real tree.
type fakeDeep struct{ res DeepResult }

func (f fakeDeep) Name() string           { return "trivy" }
func (f fakeDeep) Descriptor() Descriptor { return Descriptor{Lane: Deep} }
func (f fakeDeep) ScanTree(context.Context, ScanScope) (DeepResult, error) {
	return f.res, nil
}

func TestDeepWorker_PersistsMatchesAndOpensTriage(t *testing.T) {
	mem := store.NewMem()
	ctx := context.Background()
	repoID, _ := mem.UpsertRepo(ctx, "https://h/o/r", "/m/r.git")

	scanner := fakeDeep{res: DeepResult{Matches: []Match{
		{
			Package:      Package{PURL: "pkg:pypi/requests@2.19.0", Name: "requests", Version: "2.19.0"},
			Vuln:         Vulnerability{Source: "nvd", SourceID: "CVE-2023-1111", Kind: "CVE", Severity: "HIGH", Summary: "SSRF"},
			ToolSeverity: "CRITICAL", FixedVersion: "2.20.0",
		},
		{
			Package: Package{PURL: "pkg:pypi/urllib3@1.24.0", Name: "urllib3", Version: "1.24.0"},
			Vuln:    Vulnerability{Source: "ghsa", SourceID: "GHSA-x", Kind: "CVE", Severity: "MEDIUM"},
		},
	}}}

	// No real git: fake branch/export/tempdir.
	branch := func(context.Context, string) (string, string, error) { return "refs/heads/main", "deadbeef", nil }
	export := func(context.Context, string, string, string) error { return nil }
	tempDir := func(string) (string, func(), error) { return "/tmp/x", func() {}, nil }

	w := NewDeepWorker(scanner, mem, export, branch, tempDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := w.process(ctx, core.ScanRequest{RepoID: repoID, RepoPath: "/m/r.git"}); err != nil {
		t.Fatal(err)
	}

	matches, err := mem.VulnMatchesForRepo(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	// Sorted by SourceID: CVE-2023-1111 before GHSA-x.
	m0 := matches[0]
	if m0.SourceID != "CVE-2023-1111" || m0.PURL != "pkg:pypi/requests@2.19.0" ||
		m0.Severity != "HIGH" || m0.FixedVersion != "2.20.0" || m0.Ref != "refs/heads/main" {
		t.Fatalf("match0 = %+v", m0)
	}
	if m0.TriageStatus != "PENDING" {
		t.Errorf("triage status = %q, want PENDING", m0.TriageStatus)
	}

	// Idempotent: a re-scan must not duplicate matches or triage rows.
	if err := w.process(ctx, core.ScanRequest{RepoID: repoID, RepoPath: "/m/r.git"}); err != nil {
		t.Fatal(err)
	}
	matches2, _ := mem.VulnMatchesForRepo(ctx, repoID)
	if len(matches2) != 2 {
		t.Fatalf("after re-scan got %d matches, want 2 (idempotent)", len(matches2))
	}
}

func TestFanOut_EnqueuesToAll(t *testing.T) {
	var a, b []core.ScanRequest
	f := FanOut{enqFunc(func(r core.ScanRequest) { a = append(a, r) }), nil,
		enqFunc(func(r core.ScanRequest) { b = append(b, r) })}
	f.Enqueue(core.ScanRequest{RepoID: 7})
	if len(a) != 1 || len(b) != 1 || a[0].RepoID != 7 {
		t.Fatalf("fan-out = %v / %v", a, b)
	}
}

type enqFunc func(core.ScanRequest)

func (e enqFunc) Enqueue(r core.ScanRequest) { e(r) }

// TestDeepWorker_RealExportFeedsScanner wires the REAL git tree-export helpers
// into the worker (only Trivy is faked), proving the materialised worktree the
// scanner receives actually contains the ref-tip files.
func TestDeepWorker_RealExportFeedsScanner(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	bare := makeBareMirror(t, "requirements.txt", "requests==2.19.0\n")
	mem := store.NewMem()
	ctx := context.Background()
	repoID, _ := mem.UpsertRepo(ctx, "https://h/o/app", bare)

	// The fake scanner asserts the exported tree is real, then reports a CVE.
	checker := &treeCheckingScanner{t: t, wantFile: "requirements.txt"}
	w := NewDeepWorker(checker, mem, git.ExportTree, git.DefaultBranch, git.MkTempExport,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := w.process(ctx, core.ScanRequest{RepoID: repoID, RepoPath: bare}); err != nil {
		t.Fatal(err)
	}
	if !checker.saw {
		t.Fatal("scanner never received the worktree")
	}
	matches, _ := mem.VulnMatchesForRepo(ctx, repoID)
	if len(matches) != 1 || matches[0].SourceID != "CVE-2023-1111" {
		t.Fatalf("matches = %+v", matches)
	}
}

type treeCheckingScanner struct {
	t        *testing.T
	wantFile string
	saw      bool
}

func (s *treeCheckingScanner) Name() string           { return "trivy" }
func (s *treeCheckingScanner) Descriptor() Descriptor { return Descriptor{Lane: Deep} }
func (s *treeCheckingScanner) ScanTree(_ context.Context, scope ScanScope) (DeepResult, error) {
	s.saw = true
	if _, err := os.Stat(filepath.Join(scope.Worktree, s.wantFile)); err != nil {
		s.t.Errorf("exported worktree missing %s: %v", s.wantFile, err)
	}
	return DeepResult{Matches: []Match{{
		Package: Package{PURL: "pkg:pypi/requests@2.19.0"},
		Vuln:    Vulnerability{Source: "nvd", SourceID: "CVE-2023-1111", Kind: "CVE", Severity: "HIGH"},
	}}}, nil
}

// makeBareMirror builds a bare mirror containing one commit adding path=content.
func makeBareMirror(t *testing.T, path, content string) string {
	t.Helper()
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
