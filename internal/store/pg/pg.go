// Package pg is the Postgres core.Store — the production audit backend. Local and
// test runs use internal/store.Mem or embedded-postgres; this is the real thing.
// Queries are sqlc-generated (see sqlc/); the schema is applied with goose from
// the embedded migrations.
package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx", for goose
	"github.com/pressly/goose/v3"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/store/pg/sqlc"
	"codeberg.org/qwc/tulli/internal/verdict"
	"codeberg.org/qwc/tulli/migrations"
)

// ptr returns &s, or nil when s is empty — the sqlc convention for nullable
// text columns (empty string maps to SQL NULL).
func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

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

// ResolveVerdict applies the most-specific-wins resolver (spec §6.3): a current
// repo-wide (NULL ref) QUARANTINED blocks the whole repo; each current per-ref
// QUARANTINED is a hidden ref.
func (s *Store) ResolveVerdict(ctx context.Context, repoID int64) (core.Verdict, error) {
	rows, err := s.q.CurrentQuarantines(ctx, repoID)
	if err != nil {
		return core.Verdict{}, err
	}
	var v core.Verdict
	for _, r := range rows {
		if r.Ref == nil { // NULL ref = repo-wide quarantine
			v.RepoBlocked = true
			if r.Reason != nil {
				v.Reason = *r.Reason
			}
			continue
		}
		v.HiddenRefs = append(v.HiddenRefs, *r.Ref)
	}
	return v, nil
}

// --- Stage 4: scan results, verdict recompute inputs, reconcile inputs ---

func (s *Store) ListRepos(ctx context.Context) ([]core.RepoInfo, error) {
	rows, err := s.q.ListRepos(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.RepoInfo, len(rows))
	for i, r := range rows {
		out[i] = core.RepoInfo{ID: r.ID, MirrorPath: r.MirrorPath}
	}
	return out, nil
}

func (s *Store) InsertScan(ctx context.Context, repoID int64, scanner, scopeKind, scopeExpr string) (int64, error) {
	return s.q.InsertScan(ctx, sqlc.InsertScanParams{
		RepoID: repoID, Scanner: scanner, ScopeKind: scopeKind, ScopeExpr: ptr(scopeExpr),
	})
}

func (s *Store) InsertFinding(ctx context.Context, scanID, repoID int64, ref string, f verdict.Finding) error {
	var line *int32
	if f.Line != 0 {
		l := int32(f.Line)
		line = &l
	}
	return s.q.InsertFinding(ctx, sqlc.InsertFindingParams{
		ScanID:      scanID,
		RepoID:      &repoID,
		Ref:         ptr(ref),
		Scanner:     f.Scanner,
		Severity:    f.Severity,
		RuleID:      ptr(f.RuleID),
		FilePath:    ptr(f.FilePath),
		LineNumber:  line,
		CommitSha:   ptr(f.Commit),
		Fingerprint: ptr(f.Fingerprint),
		Description: ptr(f.Description),
	})
}

func (s *Store) FindingsForRef(ctx context.Context, repoID int64, ref string) ([]verdict.Finding, error) {
	rows, err := s.q.FindingsForRef(ctx, sqlc.FindingsForRefParams{RepoID: &repoID, Ref: ptr(ref)})
	if err != nil {
		return nil, err
	}
	out := make([]verdict.Finding, len(rows))
	for i, r := range rows {
		var line int
		if r.LineNumber != nil {
			line = int(*r.LineNumber)
		}
		out[i] = verdict.Finding{
			Scanner: r.Scanner, Severity: r.Severity, RuleID: str(r.RuleID),
			FilePath: str(r.FilePath), Line: line, Commit: str(r.CommitSha),
			Fingerprint: str(r.Fingerprint), Description: str(r.Description),
		}
	}
	return out, nil
}

func (s *Store) AffectedRefs(ctx context.Context, repoID int64) ([]string, error) {
	rows, err := s.q.AffectedRefs(ctx, &repoID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, str(r))
	}
	return out, nil
}

func (s *Store) OverriddenFingerprints(ctx context.Context, repoID int64, ref string) ([]string, error) {
	return s.q.OverriddenFingerprints(ctx, sqlc.OverriddenFingerprintsParams{RepoID: repoID, Ref: ptr(ref)})
}

func (s *Store) InsertOverride(ctx context.Context, repoID int64, ref, fingerprint, reason, actor string) error {
	return s.q.InsertOverride(ctx, sqlc.InsertOverrideParams{
		RepoID: repoID, Ref: ptr(ref), Fingerprint: fingerprint, Reason: reason, Actor: actor,
	})
}

func (s *Store) InsertVerdict(ctx context.Context, repoID int64, ref, decision, reason string) error {
	return s.q.InsertVerdict(ctx, sqlc.InsertVerdictParams{
		RepoID: repoID, Ref: ptr(ref), Decision: decision, Reason: ptr(reason),
	})
}

func (s *Store) CurrentDecision(ctx context.Context, repoID int64, ref string) (string, error) {
	d, err := s.q.CurrentDecision(ctx, sqlc.CurrentDecisionParams{RepoID: repoID, Ref: ptr(ref)})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil // no verdict yet
	}
	return d, err
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
