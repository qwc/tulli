package e2e

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/httpsrv"
	"codeberg.org/qwc/tulli/internal/mirror"
	"codeberg.org/qwc/tulli/internal/scan"
	"codeberg.org/qwc/tulli/internal/store/pg"
)

// TestE2E_RealStack_PGAndGitleaks is the docker-free equivalent of demo.sh /
// spec §12: the full secret-quarantine arc driven against the REAL wiring —
// real Postgres (embedded), the real gitleaks binary, and the reconciler's real
// periodic sweep. Unlike TestE2E_ScanQuarantineAndOverrideLift (which fakes both
// the store and the scanner), this exercises exactly what cmd/tulli/main.go
// assembles, so the parts docker-compose would have proven — real PG round
// trips, real gitleaks over a bare mirror, the out-of-process override lifted by
// the sweep ticker — are covered without a container.
//
// Skips (not fails) when git or gitleaks is absent, or embedded Postgres can't
// start; mirrors the other integration tests. gitleaks is not vendored, so this
// only runs where the binary is on PATH.
func TestE2E_RealStack_PGAndGitleaks(t *testing.T) {
	if testing.Short() {
		t.Skip("real-stack integration test; skipped under -short")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dsn := startEmbeddedPG(t)
	st, err := pg.Open(ctx, dsn) // runs migrations
	if err != nil {
		t.Fatalf("pg.Open: %v", err)
	}
	t.Cleanup(st.Close)

	// Fixture: clean main + an "evil" branch whose commit leaks a real (non-example)
	// AWS key. AKIAIOSFODNN7EXAMPLE is allowlisted by gitleaks' default ruleset, so
	// a demo-style random-but-valid AKIA is used; the aws-access-token rule fires.
	up := t.TempDir()
	repo := filepath.Join(up, "example.com/acme/widget")
	makeUpstream(t, repo, "clean main\n")
	makeUpstreamBranch(t, repo, "evil", `AWS_ACCESS_KEY_ID = "AKIAZ7X4QF2NLW8RTV3D"`+"\n")

	// Wire exactly as cmd/tulli/main.go does: real gitleaks worker + reconciler,
	// both goroutines running (the reconciler's ticker is what lifts the override).
	backend, err := git.NewBackend()
	if err != nil {
		t.Skipf("git http-backend unavailable: %v", err)
	}
	mirrors := filepath.Join(t.TempDir(), "mirrors")
	base := "file://" + up
	mir := git.NewMirror(mirrors, base, discardLogger())
	reconciler := mirror.NewReconciler(st, discardLogger())
	worker := scan.NewWorker(scan.NewGitleaks(), st, git.RefsContaining, reconciler, discardLogger())
	go worker.Run(ctx)
	go reconciler.Run(ctx, 500*time.Millisecond) // periodic safety sweep, like main.go

	gate := core.New(mir, st, worker, discardLogger())
	ts := httptest.NewServer(httpsrv.New(gate, backend, discardLogger()).Handler())
	t.Cleanup(ts.Close)
	url := ts.URL + "/repos/example.com/acme/widget"

	// 1) First fetch: served now (fail-open-once) and enqueues the async scan.
	if refs := lsRemote(t, url); !refs["refs/heads/evil"] {
		t.Fatalf("evil should be advertised on the first fetch (fail-open-once); got %v", refs)
	}

	// 2) Real gitleaks runs off-request and retro-quarantines evil. Generous
	//    timeout: scan + attribute + recompute + reconcile + PG round trips.
	waitRefGone(t, url, "refs/heads/evil", 30*time.Second)
	if refs := lsRemote(t, url); !refs["refs/heads/main"] {
		t.Errorf("clean ref main must stay advertised after quarantine; got %v", refs)
	}

	// 3) The hidden ref is withheld: a targeted clone fails, a full clone omits it.
	if out, err := exec.Command("git", "clone", "-q", "-b", "evil", url, filepath.Join(t.TempDir(), "evilclone")).CombinedOutput(); err == nil {
		t.Fatalf("clone -b evil of a quarantined ref should fail; output:\n%s", out)
	}
	full := filepath.Join(t.TempDir(), "full")
	run(t, "", "git", "clone", "-q", url, full)
	if out, _ := exec.Command("git", "-C", full, "branch", "-a").CombinedOutput(); strings.Contains(string(out), "evil") {
		t.Errorf("hidden ref evil leaked into a full clone:\n%s", out)
	}

	// 4) Read the real gitleaks finding, override its fingerprint (stands in for
	//    the stage-6 web API — a direct store write, as demo.sh does via SQL).
	repoID := onlyRepoID(t, ctx, st)
	findings, err := st.FindingsForRef(ctx, repoID, "refs/heads/evil")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("no gitleaks finding recorded for refs/heads/evil")
	}
	f := findings[0]
	if f.RuleID != "aws-access-token" || f.Fingerprint == "" {
		t.Fatalf("unexpected finding: rule=%q fp=%q", f.RuleID, f.Fingerprint)
	}
	if err := st.InsertOverride(ctx, repoID, "refs/heads/evil", f.Fingerprint, "reviewed false positive", "itsec"); err != nil {
		t.Fatal(err)
	}

	// 5) The override is out-of-process w.r.t. the scan worker; the reconciler's
	//    periodic sweep must recompute the verdict to CLEAN and re-advertise evil.
	waitRefBack(t, url, "refs/heads/evil", 30*time.Second)
	run(t, "", "git", "clone", "-q", "-b", "evil", url, filepath.Join(t.TempDir(), "evilclone2"))
}

// startEmbeddedPG boots a real Postgres in-process and returns its DSN. It uses
// a port distinct from the pg package test (54330) so a full `go test ./...` run
// (separate test binaries, possibly concurrent) does not collide.
func startEmbeddedPG(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", "/tmp/epghome") // embedded-postgres caches its binary under $HOME
	const port = 54331
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(port).
		RuntimePath(t.TempDir()).
		DataPath(t.TempDir()))
	if err := db.Start(); err != nil {
		t.Skipf("embedded postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = db.Stop() })
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port)
}

// onlyRepoID returns the id of the single mirrored repo (this test mirrors one).
func onlyRepoID(t *testing.T, ctx context.Context, st *pg.Store) int64 {
	t.Helper()
	repos, err := st.ListRepos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected exactly one mirrored repo, got %d", len(repos))
	}
	return repos[0].ID
}

// waitRefBack polls the advertisement until ref reappears or timeout (the
// override lift is applied by the reconciler's periodic sweep).
func waitRefBack(t *testing.T, url, ref string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if lsRemote(t, url)[ref] {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ref %s not re-advertised after %s — the override sweep did not lift it", ref, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
