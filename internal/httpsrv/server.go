// Package httpsrv is the HTTP door onto the core hallway: it resolves identity
// (a no-op in stage 1), parses the path, calls the gate, hands off to
// git-http-backend when allowed, and records the fetch. It depends on the
// Gate/Handoff interfaces (not concrete types) so the routing can be tested with
// fakes.
package httpsrv

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
)

// Gate is the hallway seam (implemented by *core.Gatekeeper).
type Gate interface {
	Admit(ctx context.Context, ref git.RepoRef, verb string, id auth.Identity) (core.Admission, error)
	FinishAudit(ctx context.Context, a core.Access)
}

// Handoff serves the bytes for an admitted request (implemented by *git.Backend).
type Handoff interface {
	Serve(w http.ResponseWriter, r *http.Request, repoPath, verb string)
}

type Server struct {
	gate    Gate
	authr   auth.Authenticator
	backend Handoff
	log     *slog.Logger
}

func New(gate Gate, authr auth.Authenticator, backend Handoff, log *slog.Logger) *Server {
	return &Server{gate: gate, authr: authr, backend: backend, log: log}
}

// errInvalidToken marks a present-but-unresolvable credential (surfaced as 401);
// a missing credential is anonymous, not an error.
var errInvalidToken = errors.New("invalid credentials")

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/repos/", http.HandlerFunc(s.serveRepos))
	return mux
}

func (s *Server) serveRepos(w http.ResponseWriter, r *http.Request) {
	ref, verb, err := git.ParseRequest(r.URL.Path)
	if err != nil {
		switch {
		case errors.Is(err, git.ErrUnsupported):
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

	// Identity is optional over HTTP: an anonymous fetch of a public repo is
	// allowed; a present-but-invalid token is rejected rather than silently
	// downgraded (a typo'd token shouldn't read as anonymous).
	id, err := s.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="tulli"`)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	adm, err := s.gate.Admit(r.Context(), ref, verb, id)
	if err != nil {
		s.log.Error("admit failed", "ref", ref.String(), "verb", verb, "err", err)
		http.Error(w, "upstream mirror unavailable", http.StatusBadGateway)
		return
	}
	if !adm.Allowed {
		// A real git client reads the block only as an ERR pkt-line at info/refs
		// (spec §3.3); a plain 403 there is swallowed as a generic HTTP error. For
		// the git-upload-pack POST (or a browser) a 403 with the text is right.
		if verb == git.VerbInfoRefs {
			git.WriteBlock(w, adm.BlockMsg)
		} else {
			http.Error(w, adm.BlockMsg, http.StatusForbidden)
		}
		return
	}

	s.log.Info("serve", "ref", ref.String(), "verb", verb, "service", r.URL.Query().Get("service"))
	cw := &countingWriter{ResponseWriter: w}
	s.backend.Serve(cw, r, adm.RepoPath, verb)
	s.gate.FinishAudit(r.Context(), core.Access{
		RepoID:   adm.RepoID,
		UserID:   adm.UserID,
		SourceIP: clientIP(r),
		Status:   cw.status(),
		Bytes:    cw.n,
	})
}

// authenticate resolves the request's optional credential to an identity. No
// Authorization header → anonymous (allowed for public fetch). A present token
// (bearer, or the password field of git's basic auth) that does not resolve →
// errInvalidToken.
func (s *Server) authenticate(r *http.Request) (auth.Identity, error) {
	tok, ok := requestToken(r)
	if !ok {
		return auth.Anonymous, nil
	}
	id, ok, err := s.authr.ByToken(r.Context(), tok)
	if err != nil {
		return auth.Anonymous, err
	}
	if !ok {
		return auth.Anonymous, errInvalidToken
	}
	return id, nil
}

// requestToken extracts a token from the Authorization header: a bearer token,
// or the password of HTTP basic auth (how a git client presents a token).
func requestToken(r *http.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		if t, ok := strings.CutPrefix(h, "Bearer "); ok {
			return t, true
		}
	}
	if _, pass, ok := r.BasicAuth(); ok && pass != "" {
		return pass, true
	}
	return "", false
}

// countingWriter records the response status and byte count for the audit trail
// while transparently forwarding to the underlying writer (including Flush, so
// git's streaming response isn't buffered).
type countingWriter struct {
	http.ResponseWriter
	code int
	n    int64
}

func (c *countingWriter) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer's optional
// interfaces (Flusher/Hijacker) through the wrapper.
func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *countingWriter) status() int {
	if c.code == 0 {
		return http.StatusOK
	}
	return c.code
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
