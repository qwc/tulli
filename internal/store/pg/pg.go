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

	"codeberg.org/qwc/tulli/internal/auth"
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
		out[i] = core.RepoInfo{ID: r.ID, UpstreamURL: r.UpstreamUrl, MirrorPath: r.MirrorPath}
	}
	return out, nil
}

func (s *Store) RepoByID(ctx context.Context, id int64) (core.RepoInfo, bool, error) {
	r, err := s.q.RepoByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.RepoInfo{}, false, nil
		}
		return core.RepoInfo{}, false, err
	}
	return core.RepoInfo{ID: r.ID, UpstreamURL: r.UpstreamUrl, MirrorPath: r.MirrorPath}, true, nil
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

// InsertManualBlock records a human block/lift (verdict-provenance Option B).
func (s *Store) InsertManualBlock(ctx context.Context, repoID int64, ref string, active bool, reason, actor string) error {
	return s.q.InsertManualBlock(ctx, sqlc.InsertManualBlockParams{
		RepoID: repoID, Ref: ptr(ref), Active: active, Reason: reason, Actor: actor,
	})
}

func (s *Store) ActiveManualBlock(ctx context.Context, repoID int64, ref string) (bool, string, error) {
	row, err := s.q.ActiveManualBlock(ctx, sqlc.ActiveManualBlockParams{RepoID: repoID, Ref: ptr(ref)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil // no manual block recorded
	}
	if err != nil {
		return false, "", err
	}
	return row.Active, row.Reason, nil
}

func (s *Store) ManualBlockRefs(ctx context.Context, repoID int64) ([]string, error) {
	rows, err := s.q.ManualBlockRefs(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, str(r)) // NULL ref -> "" (repo-wide)
	}
	return out, nil
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

// --- Stage 6c: deep lane (SBOM / CVE) ---

func (s *Store) InsertTreeScan(ctx context.Context, repoID int64, scanner, ref, tip string) (int64, error) {
	return s.q.InsertTreeScan(ctx, sqlc.InsertTreeScanParams{
		RepoID: repoID, Scanner: scanner, Ref: ptr(ref), TipSha: ptr(tip),
	})
}

func (s *Store) UpsertVulnerability(ctx context.Context, source, sourceID string, aliases []string, kind, severity, cvssVector, summary string) (int64, error) {
	if aliases == nil {
		aliases = []string{}
	}
	return s.q.UpsertVulnerability(ctx, sqlc.UpsertVulnerabilityParams{
		Source: source, SourceID: sourceID, Aliases: aliases, Kind: kind,
		Severity: ptr(severity), CvssVector: ptr(cvssVector), Summary: ptr(summary),
	})
}

func (s *Store) UpsertComponent(ctx context.Context, repoID int64, ref, tip, purl string, scanID int64) (int64, error) {
	return s.q.UpsertComponent(ctx, sqlc.UpsertComponentParams{
		RepoID: repoID, Ref: ptr(ref), TipSha: tip, Purl: purl, ScanID: &scanID,
	})
}

func (s *Store) UpsertVulnMatch(ctx context.Context, componentID, vulnID, scanID int64, scanner, toolSeverity, fixedVersion string) (int64, error) {
	return s.q.UpsertVulnMatch(ctx, sqlc.UpsertVulnMatchParams{
		ComponentID: componentID, VulnID: vulnID, ScanID: &scanID, Scanner: scanner,
		ToolSeverity: ptr(toolSeverity), FixedVersion: ptr(fixedVersion),
	})
}

func (s *Store) OpenTriage(ctx context.Context, repoID int64, ref string, matchID int64) error {
	return s.q.OpenTriageIfAbsent(ctx, sqlc.OpenTriageIfAbsentParams{
		RepoID: repoID, Ref: ptr(ref), MatchID: &matchID,
	})
}

func (s *Store) VulnMatchesForRepo(ctx context.Context, repoID int64) ([]core.VulnMatch, error) {
	rows, err := s.q.VulnMatchesForRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]core.VulnMatch, len(rows))
	for i, r := range rows {
		out[i] = core.VulnMatch{
			TriageID: r.TriageID, Ref: str(r.Ref), PURL: r.Purl, Source: r.Source, SourceID: r.SourceID,
			Severity: str(r.Severity), Summary: str(r.Summary),
			ToolSeverity: str(r.ToolSeverity), FixedVersion: str(r.FixedVersion),
			TriageStatus: r.TriageStatus,
		}
	}
	return out, nil
}

// --- Stage 6d: triage + notify ---

func (s *Store) ListPendingTriage(ctx context.Context) ([]core.TriageItem, error) {
	rows, err := s.q.ListPendingTriage(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.TriageItem, len(rows))
	for i, r := range rows {
		out[i] = core.TriageItem{
			TriageID: r.TriageID, RepoID: r.RepoID, Repo: r.MirrorPath,
			Ref: str(r.Ref), PURL: r.Purl, SourceID: r.SourceID, Severity: str(r.Severity),
		}
	}
	return out, nil
}

func (s *Store) TriageByID(ctx context.Context, triageID int64) (repoID int64, ref, sourceID string, ok bool, err error) {
	r, err := s.q.TriageByID(ctx, triageID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", "", false, nil
	}
	if err != nil {
		return 0, "", "", false, err
	}
	return r.RepoID, str(r.Ref), r.SourceID, true, nil
}

func (s *Store) SetTriageStatus(ctx context.Context, triageID int64, status, reviewer, note string) error {
	return s.q.SetTriageStatus(ctx, sqlc.SetTriageStatusParams{
		ID: triageID, Status: status, Reviewer: ptr(reviewer), Note: ptr(note),
	})
}

func (s *Store) RecipientsForRepo(ctx context.Context, repoID int64) ([]core.Recipient, error) {
	rows, err := s.q.RecipientsForRepo(ctx, &repoID)
	if err != nil {
		return nil, err
	}
	out := make([]core.Recipient, 0, len(rows))
	for _, r := range rows {
		var uid int64
		if r.UserID != nil {
			uid = *r.UserID
		}
		out = append(out, core.Recipient{UserID: uid, Login: r.Name})
	}
	return out, nil
}

func (s *Store) RecordNotificationForLatestVerdict(ctx context.Context, repoID int64, ref string, recipients []int64, payloadPath string) (bool, error) {
	if recipients == nil {
		recipients = []int64{}
	}
	_, err := s.q.RecordNotificationForLatestVerdict(ctx, sqlc.RecordNotificationForLatestVerdictParams{
		RepoID: repoID, Ref: ptr(ref), Recipients: recipients, PayloadPath: payloadPath,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // already notified for this verdict, or no quarantined verdict
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --- Stage 6a: identity & access (auth.Store) ---

func (s *Store) InsertUser(ctx context.Context, name string, role auth.Role, kind auth.Kind) (int64, error) {
	return s.q.InsertUser(ctx, sqlc.InsertUserParams{Name: name, Role: string(role), Kind: string(kind)})
}

func (s *Store) InsertSSHKey(ctx context.Context, userID int64, fingerprint, pubkey string) error {
	return s.q.InsertSSHKey(ctx, sqlc.InsertSSHKeyParams{UserID: userID, Fingerprint: fingerprint, Pubkey: pubkey})
}

func (s *Store) InsertToken(ctx context.Context, userID int64, tokenHash string) error {
	return s.q.InsertToken(ctx, sqlc.InsertTokenParams{UserID: userID, TokenHash: tokenHash})
}

func (s *Store) UserByFingerprint(ctx context.Context, fingerprint string) (auth.Identity, bool, error) {
	r, err := s.q.UserByFingerprint(ctx, fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Identity{}, false, nil
	}
	if err != nil {
		return auth.Identity{}, false, err
	}
	return auth.Identity{UserID: r.ID, Login: r.Name, Role: auth.Role(r.Role), Kind: auth.Kind(r.Kind)}, true, nil
}

func (s *Store) UserByTokenHash(ctx context.Context, tokenHash string) (auth.Identity, bool, error) {
	r, err := s.q.UserByTokenHash(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Identity{}, false, nil
	}
	if err != nil {
		return auth.Identity{}, false, err
	}
	return auth.Identity{UserID: r.ID, Login: r.Name, Role: auth.Role(r.Role), Kind: auth.Kind(r.Kind)}, true, nil
}

// UserByID resolves a user id to its current identity (session re-resolve).
func (s *Store) UserByID(ctx context.Context, userID int64) (auth.Identity, bool, error) {
	r, err := s.q.UserByID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Identity{}, false, nil
	}
	if err != nil {
		return auth.Identity{}, false, err
	}
	return auth.Identity{UserID: r.ID, Login: r.Name, Role: auth.Role(r.Role), Kind: auth.Kind(r.Kind)}, true, nil
}

// ListUsers returns all users, id-ordered (admin views).
func (s *Store) ListUsers(ctx context.Context) ([]auth.Identity, error) {
	rows, err := s.q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]auth.Identity, len(rows))
	for i, r := range rows {
		out[i] = auth.Identity{UserID: r.ID, Login: r.Name, Role: auth.Role(r.Role), Kind: auth.Kind(r.Kind)}
	}
	return out, nil
}

func (s *Store) InsertAccessEvent(ctx context.Context, a core.Access) error {
	p := sqlc.InsertAccessEventParams{}
	if a.RepoID != 0 {
		rid := a.RepoID
		p.RepoID = &rid
	}
	if a.UserID != 0 {
		uid := a.UserID
		p.UserID = &uid
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
