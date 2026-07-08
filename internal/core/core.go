// Package core is the transport-agnostic hallway (spec §2): identity → resolve →
// ensure → gate → serve → audit. Both the HTTP and SSH adapters make one call
// into it. Stage 2 adds the audit trail via the Store seam; gate/identity still
// arrive later behind these same seams.
package core

import (
	"context"
	"log/slog"

	"codeberg.org/qwc/tulli/internal/git"
)

// Admission is the hallway's decision. The transport serves from RepoPath (CGI
// for HTTP, exec for SSH) when Allowed, then reports the outcome via FinishAudit.
type Admission struct {
	Allowed  bool
	RepoPath string // bare mirror path the transport serves from
	RepoID   int64  // audit handle for the resolved repo (0 = not recorded)
	Verb     string
	BlockMsg string // remote: message when !Allowed (spec §3.3)
}

// Access is one recorded fetch (spec §9 access_events). Ref/commit are left for
// a later stage — they require reading the upload-pack negotiation, which we
// don't yet parse.
type Access struct {
	RepoID   int64
	SourceIP string
	Status   int
	Bytes    int64
}

// Mirror is the seam onto lazy mirroring (implemented by internal/git.Mirror).
type Mirror interface {
	EnsurePresent(ctx context.Context, ref git.RepoRef) (string, error)
	UpstreamURL(ref git.RepoRef) string
}

// Store is the persistence seam. It is deliberately dialect-agnostic so a local
// SQLite backend and a production Postgres backend can both satisfy it (see
// IMPLEMENTATION.md). The consumer (core) defines it; implementations live in
// internal/store.
type Store interface {
	UpsertRepo(ctx context.Context, upstreamURL, mirrorPath string) (int64, error)
	InsertAccessEvent(ctx context.Context, a Access) error
}

// Gatekeeper runs the policy pipeline. The gate (verdict resolver) slots in later
// without changing this signature.
type Gatekeeper struct {
	mirror Mirror
	store  Store
	log    *slog.Logger
}

func New(m Mirror, s Store, log *slog.Logger) *Gatekeeper {
	return &Gatekeeper{mirror: m, store: s, log: log}
}

// Admit runs resolve(done by the adapter) → ensure-mirrored → record-repo → gate.
func (g *Gatekeeper) Admit(ctx context.Context, ref git.RepoRef, verb string) (Admission, error) {
	// Read-only invariant (IMPLEMENTATION.md §1): never serve push.
	if verb == git.VerbReceivePack {
		return Admission{
			Allowed:  false,
			Verb:     verb,
			BlockMsg: "tulli is a read-only proxy; push (git-receive-pack) is not supported",
		}, nil
	}

	// stage 2: no gate yet — everything that mirrors successfully is allowed.
	dir, err := g.mirror.EnsurePresent(ctx, ref)
	if err != nil {
		return Admission{}, err
	}

	// Record/lookup the repo for audit. A store failure must NOT fail the fetch
	// (availability over audit-completeness); we log and serve without a repo id.
	repoID, err := g.store.UpsertRepo(ctx, g.mirror.UpstreamURL(ref), dir)
	if err != nil {
		g.log.Error("repo upsert failed; serving without audit id", "ref", ref.String(), "err", err)
		repoID = 0
	}
	return Admission{Allowed: true, RepoPath: dir, RepoID: repoID, Verb: verb}, nil
}

// FinishAudit records a served fetch. Best-effort: audit-store errors are logged,
// never surfaced to the client.
func (g *Gatekeeper) FinishAudit(ctx context.Context, a Access) {
	if a.RepoID == 0 {
		return // repo wasn't recorded; nothing to attribute the event to
	}
	if err := g.store.InsertAccessEvent(ctx, a); err != nil {
		g.log.Error("audit insert failed", "repo_id", a.RepoID, "err", err)
	}
}
