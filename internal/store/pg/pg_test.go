package pg

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"codeberg.org/qwc/tulli/internal/core"
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
