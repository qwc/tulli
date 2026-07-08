// Package pg is the Postgres core.Store — the production audit backend. Local and
// test runs use internal/store.Mem or embedded-postgres; this is the real thing.
// Queries are sqlc-generated (see sqlc/); the schema is applied with goose from
// the embedded migrations.
package pg

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx", for goose
	"github.com/pressly/goose/v3"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/store/pg/sqlc"
	"codeberg.org/qwc/tulli/migrations"
)

// Store is a Postgres-backed core.Store.
type Store struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

var _ core.Store = (*Store)(nil)

// Open runs migrations, connects a pool, and returns the store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	if err := Migrate(dsn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool, q: sqlc.New(pool)}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Migrate applies the embedded goose migrations via a temporary database/sql conn.
func Migrate(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}

func (s *Store) UpsertRepo(ctx context.Context, upstreamURL, mirrorPath string) (int64, error) {
	return s.q.UpsertRepo(ctx, sqlc.UpsertRepoParams{UpstreamUrl: upstreamURL, MirrorPath: mirrorPath})
}

func (s *Store) InsertAccessEvent(ctx context.Context, a core.Access) error {
	p := sqlc.InsertAccessEventParams{}
	if a.RepoID != 0 {
		rid := a.RepoID
		p.RepoID = &rid
	}
	if a.Status != 0 {
		st := int32(a.Status)
		p.HttpStatus = &st
	}
	if a.Bytes != 0 {
		b := a.Bytes
		p.Bytes = &b
	}
	if a.SourceIP != "" {
		if addr, err := netip.ParseAddr(a.SourceIP); err == nil {
			p.SourceIp = &addr
		}
	}
	return s.q.InsertAccessEvent(ctx, p)
}
