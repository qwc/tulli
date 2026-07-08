// Package core is the transport-agnostic hallway (spec §2): identity → resolve →
// ensure → gate → serve → audit. Both the HTTP and SSH adapters make one call
// into it. This is the stage-1 skeleton: resolve + ensure only; gate, identity,
// and audit arrive in later stages behind these same seams.
package core

import (
	"context"
	"log/slog"

	"codeberg.org/qwc/tulli/internal/git"
)

// Admission is the hallway's decision. The transport does the actual serve from
// RepoPath (CGI for HTTP, exec for SSH) when Allowed, then calls FinishAudit.
type Admission struct {
	Allowed  bool
	RepoPath string // bare mirror path the transport serves from
	Verb     string
	BlockMsg string // remote: message when !Allowed (spec §3.3)
	AuditID  int64  // handle to close out after serve (stage 2+)
}

// Mirror is the seam onto lazy mirroring (implemented by internal/git.Mirror).
type Mirror interface {
	EnsurePresent(ctx context.Context, ref git.RepoRef) (string, error)
}

// Gatekeeper runs the policy pipeline. Stage 1 wires only the mirror; the gate
// (verdict resolver) and store slot in later without changing this signature.
type Gatekeeper struct {
	mirror Mirror
	log    *slog.Logger
}

func New(m Mirror, log *slog.Logger) *Gatekeeper {
	return &Gatekeeper{mirror: m, log: log}
}

// Admit runs resolve(done by the adapter) → ensure-mirrored → gate → open-audit.
func (g *Gatekeeper) Admit(ctx context.Context, ref git.RepoRef, verb string) (Admission, error) {
	// Read-only invariant (IMPLEMENTATION.md §1): never serve push.
	if verb == git.VerbReceivePack {
		return Admission{
			Allowed:  false,
			Verb:     verb,
			BlockMsg: "tulli is a read-only proxy; push (git-receive-pack) is not supported",
		}, nil
	}

	// stage 1: no gate yet — everything that mirrors successfully is allowed.
	dir, err := g.mirror.EnsurePresent(ctx, ref)
	if err != nil {
		return Admission{}, err
	}
	return Admission{Allowed: true, RepoPath: dir, Verb: verb}, nil
}

// FinishAudit records the outcome of a served request. No-op until the store
// lands (stage 2).
func (g *Gatekeeper) FinishAudit(ctx context.Context, id int64, status int, bytes int64) {}
