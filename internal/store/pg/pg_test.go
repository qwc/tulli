package pg

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// startPG boots a real embedded Postgres for integration testing. Skipped in
// -short; skipped (not failed) if the binary can't be fetched/started.
func startPG(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping postgres integration test in -short")
	}
	// embedded-postgres caches its download under $HOME; point it at a writable dir.
	t.Setenv("HOME", "/tmp/epghome")
	const port = 54330
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

func TestPG_MigrateUpsertAndAudit(t *testing.T) {
	dsn := startPG(t)
	ctx := context.Background()

	s, err := Open(ctx, dsn) // also runs migrations
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// UpsertRepo is idempotent on upstream_url.
	id1, err := s.UpsertRepo(ctx, "https://github.com/o/r", "/m/r.git")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.UpsertRepo(ctx, "https://github.com/o/r", "/m/r.git")
	if err != nil || id1 != id2 {
		t.Fatalf("upsert not idempotent: %d vs %d (err %v)", id1, id2, err)
	}
	id3, err := s.UpsertRepo(ctx, "https://github.com/o/other", "/m/other.git")
	if err != nil || id3 == id1 {
		t.Fatalf("distinct upstream must get a new id: %d (err %v)", id3, err)
	}

	// InsertAccessEvent persists the fetch, including the INET source_ip.
	if err := s.InsertAccessEvent(ctx, core.Access{RepoID: id1, SourceIP: "1.2.3.4", Status: 200, Bytes: 123}); err != nil {
		t.Fatal(err)
	}

	var (
		ip     netip.Addr
		bytes  int64
		status int32
	)
	err = s.pool.QueryRow(ctx,
		`SELECT source_ip, bytes, http_status FROM access_events WHERE repo_id=$1`, id1).
		Scan(&ip, &bytes, &status)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "1.2.3.4" || bytes != 123 || status != 200 {
		t.Fatalf("access row = ip:%s bytes:%d status:%d", ip, bytes, status)
	}
}

func TestPG_ResolveVerdict(t *testing.T) {
	dsn := startPG(t)
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.UpsertRepo(ctx, "https://github.com/o/verdicts", "/m/v.git")
	if err != nil {
		t.Fatal(err)
	}

	// No verdicts yet → clean.
	if v, err := s.ResolveVerdict(ctx, id); err != nil || v.RepoBlocked || len(v.HiddenRefs) != 0 {
		t.Fatalf("empty verdict = %+v (err %v), want clean", v, err)
	}

	insertVerdict := func(ref, decision, reason string) {
		t.Helper()
		var refArg any
		if ref != "" {
			refArg = ref
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO verdicts (repo_id, ref, decision, reason) VALUES ($1,$2,$3,$4)`,
			id, refArg, decision, reason); err != nil {
			t.Fatal(err)
		}
	}

	// Ref-level quarantine on evil; a newer CLEAN must clear an older QUARANTINED
	// on good (most-recent-per-ref wins, spec §6.3).
	insertVerdict("refs/heads/evil", "QUARANTINED", "secret")
	insertVerdict("refs/heads/good", "QUARANTINED", "oops")
	insertVerdict("refs/heads/good", "CLEAN", "rescanned")

	v, err := s.ResolveVerdict(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if v.RepoBlocked {
		t.Errorf("no repo-wide row yet, RepoBlocked should be false: %+v", v)
	}
	if len(v.HiddenRefs) != 1 || v.HiddenRefs[0] != "refs/heads/evil" {
		t.Fatalf("hidden refs = %v, want just refs/heads/evil (good was re-cleaned)", v.HiddenRefs)
	}

	// A repo-wide QUARANTINED (NULL ref) blocks the whole repo, reason surfaced.
	insertVerdict("", "QUARANTINED", "toxic repo")
	v, err = s.ResolveVerdict(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !v.RepoBlocked || v.Reason != "toxic repo" {
		t.Fatalf("verdict = %+v, want RepoBlocked with reason 'toxic repo'", v)
	}
}

// Exercise the stage-4 scan/recompute path against real Postgres: migration
// 00002, the nullable-column pointer wrappers, and the override→CLEAN recompute.
func TestPG_ScanFindingsAndRecompute(t *testing.T) {
	dsn := startPG(t)
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.UpsertRepo(ctx, "https://github.com/o/scan", "/m/scan.git")
	if err != nil {
		t.Fatal(err)
	}
	if repos, err := s.ListRepos(ctx); err != nil || len(repos) == 0 {
		t.Fatalf("ListRepos = %v, %v", repos, err)
	}

	scanID, err := s.InsertScan(ctx, id, "gitleaks", "RANGE", "--all")
	if err != nil {
		t.Fatal(err)
	}
	fnd := verdict.Finding{
		Scanner: "gitleaks", Severity: verdict.SeverityHigh, RuleID: "aws",
		FilePath: "cfg.yml", Line: 3, Commit: "c0ffee", Fingerprint: "fp1", Description: "AWS key",
	}
	if err := s.InsertFinding(ctx, scanID, id, "refs/heads/evil", fnd); err != nil {
		t.Fatal(err)
	}

	// Read-back round-trips the nullable columns.
	got, err := s.FindingsForRef(ctx, id, "refs/heads/evil")
	if err != nil || len(got) != 1 || got[0].Fingerprint != "fp1" || got[0].Line != 3 || got[0].Commit != "c0ffee" {
		t.Fatalf("FindingsForRef = %+v, %v", got, err)
	}
	if refs, err := s.AffectedRefs(ctx, id); err != nil || len(refs) != 1 || refs[0] != "refs/heads/evil" {
		t.Fatalf("AffectedRefs = %v, %v", refs, err)
	}

	// Recompute → QUARANTINED, and it shows up as a hidden ref.
	if err := verdict.RecomputeRepo(ctx, s, id); err != nil {
		t.Fatal(err)
	}
	if d, err := s.CurrentDecision(ctx, id, "refs/heads/evil"); err != nil || d != verdict.DecisionQuarantined {
		t.Fatalf("decision = %q, %v, want QUARANTINED", d, err)
	}
	v, _ := s.ResolveVerdict(ctx, id)
	if len(v.HiddenRefs) != 1 || v.HiddenRefs[0] != "refs/heads/evil" {
		t.Fatalf("hidden refs = %v, want evil", v.HiddenRefs)
	}

	// Override the fingerprint → recompute → CLEAN (spec §12 step 4).
	if err := s.InsertOverride(ctx, id, "refs/heads/evil", "fp1", "false positive", "itsec"); err != nil {
		t.Fatal(err)
	}
	if err := verdict.RecomputeRepo(ctx, s, id); err != nil {
		t.Fatal(err)
	}
	if d, err := s.CurrentDecision(ctx, id, "refs/heads/evil"); err != nil || d != verdict.DecisionClean {
		t.Fatalf("after override decision = %q, %v, want CLEAN", d, err)
	}
}
