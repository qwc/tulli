// Package httpsrv is the HTTP door onto the core hallway: it resolves identity
// (a no-op in stage 1), parses the path, calls the gate, and — when allowed —
// hands off to git-http-backend. ~one screen of adapter; the policy lives in
// core. It depends on the Gate/Handoff interfaces (not concrete types) so the
// routing can be tested with fakes.
package httpsrv

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
)

// Gate is the hallway seam (implemented by *core.Gatekeeper).
type Gate interface {
	Admit(ctx context.Context, ref git.RepoRef, verb string) (core.Admission, error)
	FinishAudit(ctx context.Context, id int64, status int, n int64)
}

// Handoff serves the bytes for an admitted request (implemented by *git.Backend).
type Handoff interface {
	Serve(w http.ResponseWriter, r *http.Request, repoPath, verb string)
}

type Server struct {
	gate    Gate
	backend Handoff
	log     *slog.Logger
}

func New(gate Gate, backend Handoff, log *slog.Logger) *Server {
	return &Server{gate: gate, backend: backend, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	// All git smart-HTTP traffic; we parse the verb from the path ourselves
	// rather than registering many patterns.
	mux.Handle("/repos/", http.HandlerFunc(s.serveRepos))
	return mux
}

func (s *Server) serveRepos(w http.ResponseWriter, r *http.Request) {
	ref, verb, err := git.ParseRequest(r.URL.Path)
	if err != nil {
		switch {
		case errors.Is(err, git.ErrUnsupported):
			// Dumb-protocol / unknown endpoint.
			http.Error(w, "tulli serves the git smart protocol only", http.StatusNotFound)
		default:
			http.Error(w, "bad repo path", http.StatusBadRequest)
		}
		return
	}

	// Read-only: refuse push at the door (defense-in-depth with core.Admit).
	if verb == git.VerbReceivePack || r.URL.Query().Get("service") == git.VerbReceivePack {
		http.Error(w, "tulli is read-only; push is not supported", http.StatusForbidden)
		return
	}

	adm, err := s.gate.Admit(r.Context(), ref, verb)
	if err != nil {
		s.log.Error("admit failed", "ref", ref.String(), "verb", verb, "err", err)
		http.Error(w, "upstream mirror unavailable", http.StatusBadGateway)
		return
	}
	if !adm.Allowed {
		http.Error(w, adm.BlockMsg, http.StatusForbidden)
		return
	}

	s.log.Info("serve", "ref", ref.String(), "verb", verb, "service", r.URL.Query().Get("service"))
	s.backend.Serve(w, r, adm.RepoPath, verb)
	s.gate.FinishAudit(r.Context(), adm.AuditID, http.StatusOK, 0)
}
