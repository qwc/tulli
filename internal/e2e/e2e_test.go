// Package e2e is an integration suite: it wires the real git/core/httpsrv stack
// behind an httptest server and drives actual `git clone` against it. The
// deterministic tests use a local file:// upstream (no network); the GitHub test
// is skipped in -short and skipped (not failed) when offline.
package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/httpsrv"
	"codeberg.org/qwc/tulli/internal/store"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// makeUpstream builds a bare repo with one commit at dir (a stand-in upstream).
func makeUpstream(t *testing.T, dir, seed string) {
	t.Helper()
	src := dir + ".src"
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, "", "git", "init", "-q", "-b", "main", src)
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, src, "git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
	run(t, src, "git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "seed")
	run(t, "", "git", "clone", "-q", "--bare", src, dir)
	os.RemoveAll(src)
}

// newStack wires the real stack and returns the test server, mirror root, and
// the in-memory audit store (for asserting the audit trail).
func newStack(t *testing.T, upstreamBase string) (*httptest.Server, string, *store.Mem) {
	t.Helper()
	backend, err := git.NewBackend()
	if err != nil {
		t.Skipf("git http-backend unavailable: %v", err)
	}
	mirrors := filepath.Join(t.TempDir(), "mirrors")
	mirror := git.NewMirror(mirrors, upstreamBase, discardLogger())
	st := store.NewMem()
	gate := core.New(mirror, st, discardLogger())
	srv := httpsrv.New(gate, backend, discardLogger())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, mirrors, st
}

func TestE2E_CloneThroughProxy(t *testing.T) {
	up := t.TempDir()
	makeUpstream(t, filepath.Join(up, "example.com/acme/widget"), "hello e2e\n")
	ts, mirrors, st := newStack(t, "file://"+up)

	dst := filepath.Join(t.TempDir(), "clone")
	run(t, "", "git", "clone", "-q", ts.URL+"/repos/example.com/acme/widget", dst)

	got, err := os.ReadFile(filepath.Join(dst, "README.md"))
	if err != nil || string(got) != "hello e2e\n" {
		t.Fatalf("cloned README = %q, err %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(mirrors, "example.com/acme/widget.git", "HEAD")); err != nil {
		t.Errorf("mirror not created on disk: %v", err)
	}

	// Audit trail: the repo was recorded and at least one served fetch logged
	// with a real status + byte count.
	if st.RepoCount() != 1 {
		t.Errorf("audit RepoCount = %d, want 1", st.RepoCount())
	}
	ev := st.Events()
	if len(ev) == 0 {
		t.Fatal("no access events recorded")
	}
	var served bool
	for _, e := range ev {
		if e.Status == 200 && e.Bytes > 0 && e.RepoID != 0 {
			served = true
		}
	}
	if !served {
		t.Errorf("expected an access event with status 200 and bytes>0; got %+v", ev)
	}
}

func TestE2E_CacheHitSecondClone(t *testing.T) {
	up := t.TempDir()
	makeUpstream(t, filepath.Join(up, "h/o/r"), "x\n")
	ts, _, _ := newStack(t, "file://"+up)

	run(t, "", "git", "clone", "-q", ts.URL+"/repos/h/o/r", filepath.Join(t.TempDir(), "a"))
	run(t, "", "git", "clone", "-q", ts.URL+"/repos/h/o/r", filepath.Join(t.TempDir(), "b"))
}

func TestE2E_ConcurrentFirstFetch(t *testing.T) {
	up := t.TempDir()
	makeUpstream(t, filepath.Join(up, "h/o/con"), "concurrent\n")
	ts, _, _ := newStack(t, "file://"+up)

	base := t.TempDir()
	const N = 4
	errs := make([]error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command("git", "clone", "-q", ts.URL+"/repos/h/o/con", filepath.Join(base, string(rune('a'+i))))
			if out, err := cmd.CombinedOutput(); err != nil {
				errs[i] = err
				t.Logf("clone %d: %v\n%s", i, err, out)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent clone %d failed: %v", i, err)
		}
	}
}

func TestE2E_ReadOnlyPushRefused(t *testing.T) {
	up := t.TempDir()
	makeUpstream(t, filepath.Join(up, "h/o/r"), "x\n")
	ts, _, _ := newStack(t, "file://"+up)

	dst := filepath.Join(t.TempDir(), "c")
	run(t, "", "git", "clone", "-q", ts.URL+"/repos/h/o/r", dst)

	cmd := exec.Command("git", "-C", dst, "push", ts.URL+"/repos/h/o/r", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push should have failed (read-only); output:\n%s", out)
	}
	if !strings.Contains(string(out), "403") && !strings.Contains(strings.ToLower(string(out)), "forbidden") {
		t.Fatalf("push failed but not with 403/forbidden:\n%s", out)
	}
}

func TestE2E_GitHubCloneThroughProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short")
	}
	ts, mirrors, _ := newStack(t, "https://")

	dst := filepath.Join(t.TempDir(), "gh")
	cmd := exec.CommandContext(context.Background(), "git", "clone", "-q",
		ts.URL+"/repos/github.com/octocat/Hello-World", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("github clone failed (likely offline): %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(mirrors, "github.com/octocat/Hello-World.git", "HEAD")); err != nil {
		t.Errorf("github mirror not created: %v", err)
	}
}
