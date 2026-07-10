// Package core is the transport-agnostic hallway (spec §2): identity → resolve →
// ensure → gate → serve → audit. Both the HTTP and SSH adapters make one call
// into it. The gate (verdict resolver + hideRefs reconcile) and audit trail run
// here behind the Store/Mirror seams; identity and the scanners that write
// verdicts arrive in later stages behind those same seams.
package core

import (
	"context"
	"log/slog"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/git"
)

// Admission is the hallway's decision. The transport serves from RepoPath (CGI
// for HTTP, exec for SSH) when Allowed, then reports the outcome via FinishAudit.
type Admission struct {
	Allowed  bool
	RepoPath string // bare mirror path the transport serves from
	RepoID   int64  // audit handle for the resolved repo (0 = not recorded)
	UserID   int64  // resolved principal for the audit trail (0 = anonymous)
	Verb     string
	BlockMsg string // remote: message when !Allowed (spec §3.3)
}

// RepoInfo identifies a mirrored repo for the reconcile sweep (id + on-disk path).
type RepoInfo struct {
	ID         int64
	MirrorPath string
}

// Access is one recorded fetch (spec §9 access_events). Ref/commit are left for
// a later stage — they require reading the upload-pack negotiation, which we
// don't yet parse.
type Access struct {
	RepoID   int64
	UserID   int64 // resolved principal (0 = anonymous)
	SourceIP string
	Status   int
	Bytes    int64
}

// VulnMatch is the read model for a CVE match on a repo (spec §8.5): a package
// (PURL) affected by an advisory, with its current triage status. Purely
// informational — CVE matches never gate (§6.6). TriageID is the triage row to
// act on (§6d).
type VulnMatch struct {
	TriageID     int64
	Ref          string
	PURL         string
	Source       string
	SourceID     string
	Severity     string
	Summary      string
	ToolSeverity string
	FixedVersion string
	TriageStatus string
}

// TriageItem is one PENDING triage row for the queue view (§6d): a CVE match
// awaiting a human decision, with enough context to act on and to block.
type TriageItem struct {
	TriageID int64
	RepoID   int64
	Repo     string // mirror path (display)
	Ref      string
	PURL     string
	SourceID string
	Severity string
}

// Recipient is a user to notify, resolved from the audit trail (§6d).
type Recipient struct {
	UserID int64
	Login  string
}

// Mirror is the seam onto lazy mirroring (implemented by internal/git.Mirror).
type Mirror interface {
	// EnsurePresent returns the mirror path and whether it was just created
	// (created == true only on the first fetch — the fail-open-once scan trigger).
	EnsurePresent(ctx context.Context, ref git.RepoRef) (path string, created bool, err error)
	UpstreamURL(ref git.RepoRef) string
	// SetHiddenRefs reconciles the mirror's ref-level quarantine so upload-pack
	// hides exactly refs (spec §6.4).
	SetHiddenRefs(ctx context.Context, repoPath string, refs []string) error
}

// ScanRequest is a fail-open-once scan enqueued after a first fetch (spec §7).
// Range is a git revision range to scan; "" means the whole in-window history.
type ScanRequest struct {
	RepoID   int64
	RepoPath string
	Range    string
}

// Enqueuer hands a scan to the async worker. Non-blocking from the request path
// (implemented by internal/scan.Worker). A nil Enqueuer disables scanning.
type Enqueuer interface {
	Enqueue(req ScanRequest)
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

// Gatekeeper runs the policy pipeline: resolve → ensure → gate → (enqueue scan).
type Gatekeeper struct {
	mirror   Mirror
	store    Store
	enqueuer Enqueuer // may be nil (scanning disabled)
	log      *slog.Logger
}

func New(m Mirror, s Store, enq Enqueuer, log *slog.Logger) *Gatekeeper {
	return &Gatekeeper{mirror: m, store: s, enqueuer: enq, log: log}
}

// Admit runs resolve(done by the adapter) → ensure-mirrored → record-repo → gate.
// The identity was resolved by the transport adapter (SSH pubkey / HTTP token)
// and is stamped onto the returned Admission for the audit trail; the git-serving
// path does not yet authorize by role (public FOSS is anonymously fetchable), but
// this is the seam a later identity-aware gate (private repos, per-user policy)
// hooks into.
func (g *Gatekeeper) Admit(ctx context.Context, ref git.RepoRef, verb string, id auth.Identity) (adm Admission, err error) {
	// Every admission (allow or block) is attributed to the resolved principal.
	defer func() { adm.UserID = id.UserID }()

	// Read-only invariant (IMPLEMENTATION.md §1): never serve push.
	if verb == git.VerbReceivePack {
		return Admission{
			Allowed:  false,
			Verb:     verb,
			BlockMsg: "tulli is a read-only proxy; push (git-receive-pack) is not supported",
		}, nil
	}

	dir, created, err := g.mirror.EnsurePresent(ctx, ref)
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

	// Fail-open-once (spec §7): the first fetch of a freshly-mirrored repo is
	// served now and scanned asynchronously; a HIGH secret retro-quarantines it
	// for the next fetch. Only on creation, so a warm cache never re-scans here.
	if created && g.enqueuer != nil {
		g.enqueuer.Enqueue(ScanRequest{RepoID: repoID, RepoPath: dir})
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
