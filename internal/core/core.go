// Package core is the transport-agnostic hallway (spec §2): identity → resolve →
// ensure → gate → serve → audit. Both the HTTP and SSH adapters make one call
// into it. The gate (verdict resolver + hideRefs reconcile) and audit trail run
// here behind the Store/Mirror seams; identity and the scanners that write
// verdicts arrive in later stages behind those same seams.
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
	// SetHiddenRefs reconciles the mirror's ref-level quarantine so upload-pack
	// hides exactly refs (spec §6.4).
	SetHiddenRefs(ctx context.Context, repoPath string, refs []string) error
}

// Verdict is the gate's enforcement view of a repo, resolved most-specific-wins
// (spec §6.3): a repo-wide QUARANTINED row blocks the whole repo; specific-ref
// QUARANTINED rows are enforced by hiding those refs. RepoBlocked takes
// precedence — a repo-wide quarantine can't be lifted by a per-ref waiver
// (spec §6.7 guardrail).
type Verdict struct {
	RepoBlocked bool     // repo-wide QUARANTINED — refuse the whole fetch
	Reason      string   // operator message for the repo-wide block
	HiddenRefs  []string // ref-level QUARANTINED refs to hide (spec §6.4)
}

// Store is the persistence seam. It is deliberately dialect-agnostic so a local
// SQLite backend and a production Postgres backend can both satisfy it (see
// IMPLEMENTATION.md). The consumer (core) defines it; implementations live in
// internal/store.
type Store interface {
	UpsertRepo(ctx context.Context, upstreamURL, mirrorPath string) (int64, error)
	InsertAccessEvent(ctx context.Context, a Access) error
	// ResolveVerdict returns the current enforcement verdict for a repo
	// (most-specific-wins over the verdicts table, spec §6.3).
	ResolveVerdict(ctx context.Context, repoID int64) (Verdict, error)
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

	dir, err := g.mirror.EnsurePresent(ctx, ref)
	if err != nil {
		return Admission{}, err
	}

	// Record/lookup the repo for audit. A store failure must NOT fail the fetch
	// (availability over audit-completeness); we log and serve without a repo id.
	// It also means we have no repo handle to resolve a verdict against, so the
	// gate is skipped — a DB outage fails open (documented prototype limitation;
	// repo-wide quarantine relies on DB availability, ref-level blocks persist on
	// disk via hideRefs).
	repoID, err := g.store.UpsertRepo(ctx, g.mirror.UpstreamURL(ref), dir)
	if err != nil {
		g.log.Error("repo upsert failed; serving without audit id or gate", "ref", ref.String(), "err", err)
		return Admission{Allowed: true, RepoPath: dir, RepoID: 0, Verb: verb}, nil
	}

	// Gate (spec §6.3): resolve the enforcement verdict for this repo.
	v, err := g.store.ResolveVerdict(ctx, repoID)
	if err != nil {
		// A transient verdict-query failure fails open (serve) rather than taking
		// down every fetch; ref-level blocks already reconciled on disk still
		// hold. Logged loudly so it is not silent.
		g.log.Error("verdict resolve failed; serving without gate", "ref", ref.String(), "repo_id", repoID, "err", err)
		return Admission{Allowed: true, RepoPath: dir, RepoID: repoID, Verb: verb}, nil
	}

	if v.RepoBlocked {
		return Admission{Allowed: false, RepoID: repoID, Verb: verb, BlockMsg: blockMsg(v.Reason)}, nil
	}

	// Ref-level quarantine: make the mirror hide exactly the bad refs (spec §6.4).
	// If we cannot enforce a known ref-level block, we must not serve — an
	// unhidden quarantined ref would leak — so this fails CLOSED for the repo.
	if len(v.HiddenRefs) > 0 {
		if err := g.mirror.SetHiddenRefs(ctx, dir, v.HiddenRefs); err != nil {
			g.log.Error("hideRefs reconcile failed; blocking repo to avoid leak", "ref", ref.String(), "repo_id", repoID, "err", err)
			return Admission{Allowed: false, RepoID: repoID, Verb: verb,
				BlockMsg: "tulli: enforcement temporarily unavailable, try again shortly"}, nil
		}
	}

	return Admission{Allowed: true, RepoPath: dir, RepoID: repoID, Verb: verb}, nil
}

// blockMsg composes the operator message git shows for a repo-wide quarantine.
func blockMsg(reason string) string {
	if reason == "" {
		return "tulli: repo QUARANTINED"
	}
	return "tulli: repo QUARANTINED — " + reason
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
