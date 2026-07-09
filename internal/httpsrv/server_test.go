package httpsrv

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type admitFunc func(ctx context.Context, ref git.RepoRef, verb string, id auth.Identity) (core.Admission, error)

type fakeGate struct {
	admitFn     admitFunc
	admitCalls  int
	finishCalls int
	gotRef      git.RepoRef
	gotVerb     string
	gotID       auth.Identity
	gotAccess   core.Access
}

func (f *fakeGate) Admit(ctx context.Context, ref git.RepoRef, verb string, id auth.Identity) (core.Admission, error) {
	f.admitCalls++
	f.gotRef, f.gotVerb, f.gotID = ref, verb, id
	adm, err := f.admitFn(ctx, ref, verb, id)
	adm.UserID = id.UserID // mirror the real Gatekeeper stamping the principal
	return adm, err
}
func (f *fakeGate) FinishAudit(_ context.Context, a core.Access) {
	f.finishCalls++
	f.gotAccess = a
}

// fakeAuth resolves tokens/keys from fixed maps (empty = everything anonymous).
type fakeAuth struct {
	tokens map[string]auth.Identity
	keys   map[string]auth.Identity
}

func (f fakeAuth) ByToken(_ context.Context, tok string) (auth.Identity, bool, error) {
	id, ok := f.tokens[tok]
	return id, ok, nil
}
func (f fakeAuth) ByPublicKey(_ context.Context, fp string) (auth.Identity, bool, error) {
	id, ok := f.keys[fp]
	return id, ok, nil
}

type fakeHandoff struct {
	called   bool
	repoPath string
	verb     string
}

func (f *fakeHandoff) Serve(w http.ResponseWriter, _ *http.Request, repoPath, verb string) {
	f.called, f.repoPath, f.verb = true, repoPath, verb
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("SERVED"))
}

func newTestServer(admit admitFunc) (*Server, *fakeGate, *fakeHandoff) {
	g := &fakeGate{admitFn: admit}
	h := &fakeHandoff{}
	return New(g, fakeAuth{}, h, discardLogger()), g, h
}

func do(srv *Server, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func allow(path string) admitFunc {
	return func(_ context.Context, _ git.RepoRef, verb string, _ auth.Identity) (core.Admission, error) {
		return core.Admission{Allowed: true, RepoPath: path, RepoID: 42, Verb: verb}, nil
	}
}

func TestHealthz(t *testing.T) {
	srv, _, _ := newTestServer(allow("/m/x.git"))
	rr := do(srv, "GET", "/healthz")
	if rr.Code != http.StatusOK || rr.Body.String() != "ok\n" {
		t.Fatalf("healthz = %d %q", rr.Code, rr.Body.String())
	}
}

func TestServeRepos_AllowedHandsOff(t *testing.T) {
	srv, g, h := newTestServer(allow("/mirrors/github.com/o/r.git"))
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack")

	if rr.Code != http.StatusOK || rr.Body.String() != "SERVED" {
		t.Fatalf("got %d %q, want 200 SERVED", rr.Code, rr.Body.String())
	}
	if !h.called || h.repoPath != "/mirrors/github.com/o/r.git" || h.verb != git.VerbInfoRefs {
		t.Errorf("handoff = %+v", h)
	}
	if g.gotRef.Host != "github.com" || g.gotRef.Path != "o/r" || g.gotVerb != git.VerbInfoRefs {
		t.Errorf("gate got ref=%v verb=%q", g.gotRef, g.gotVerb)
	}
	if g.finishCalls != 1 {
		t.Errorf("FinishAudit calls = %d, want 1", g.finishCalls)
	}
	// The audit must capture the served status + byte count (len("SERVED")=6)
	// and carry the admission's repo id.
	if g.gotAccess.RepoID != 42 || g.gotAccess.Status != http.StatusOK || g.gotAccess.Bytes != 6 {
		t.Errorf("audit access = %+v, want {RepoID:42 Status:200 Bytes:6}", g.gotAccess)
	}
}

func TestServeRepos_PushRefusedAtDoor(t *testing.T) {
	srv, g, h := newTestServer(allow("x"))
	rr := do(srv, "POST", "/repos/github.com/o/r/git-receive-pack")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("push status = %d, want 403", rr.Code)
	}
	if g.admitCalls != 0 || h.called {
		t.Errorf("push must not reach gate/handoff (admit=%d handoff=%v)", g.admitCalls, h.called)
	}
}

func TestServeRepos_ReceivePackServiceRefused(t *testing.T) {
	srv, g, _ := newTestServer(allow("x"))
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-receive-pack")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if g.admitCalls != 0 {
		t.Errorf("receive-pack advertisement must be refused at the door")
	}
}

func TestServeRepos_AdmitErrorIsBadGateway(t *testing.T) {
	srv, _, _ := newTestServer(func(context.Context, git.RepoRef, string, auth.Identity) (core.Admission, error) {
		return core.Admission{}, io.ErrUnexpectedEOF
	})
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
}

// At info/refs a block must be an ERR pkt-line (200 body), which is the only
// form a real git client surfaces (spec §3.3) — not a plain 403.
func TestServeRepos_QuarantinedInfoRefsWritesErrPktLine(t *testing.T) {
	srv, _, h := newTestServer(func(context.Context, git.RepoRef, string, auth.Identity) (core.Admission, error) {
		return core.Admission{Allowed: false, BlockMsg: "tulli: repo QUARANTINED — secret"}, nil
	})
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (git only reads the ERR body on 2xx)", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("content-type = %q, want the upload-pack advertisement type", ct)
	}
	if h.called {
		t.Error("blocked request must not hand off")
	}
	body := rr.Body.String()
	// pkt-line: 4 hex length digits, then "ERR <msg>".
	if len(body) < 8 || !strings.HasPrefix(body[4:], "ERR ") {
		t.Fatalf("body = %q, want a 4-hex-prefixed ERR pkt-line", body)
	}
	if !strings.Contains(body, "QUARANTINED") {
		t.Errorf("body = %q, want it to carry the block message", body)
	}
}

// A blocked git-upload-pack POST (or a browser) gets a plain 403 with the text.
func TestServeRepos_QuarantinedUploadPackIsForbidden(t *testing.T) {
	srv, _, h := newTestServer(func(context.Context, git.RepoRef, string, auth.Identity) (core.Admission, error) {
		return core.Admission{Allowed: false, BlockMsg: "tulli: repo QUARANTINED"}, nil
	})
	rr := do(srv, "POST", "/repos/github.com/o/r/git-upload-pack")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if h.called {
		t.Error("blocked request must not hand off")
	}
	if !strings.Contains(rr.Body.String(), "QUARANTINED") {
		t.Errorf("body = %q, want the block message", rr.Body.String())
	}
}

// A bearer token resolves to an identity that is passed to the gate and recorded
// in the audit trail (stage 6a).
func TestServeRepos_TokenIdentityAudited(t *testing.T) {
	g := &fakeGate{admitFn: allow("/m/x.git")}
	authr := fakeAuth{tokens: map[string]auth.Identity{"s3cret": {UserID: 5, Login: "ci-bot", Kind: auth.KindRobot}}}
	srv := New(g, authr, &fakeHandoff{}, discardLogger())

	req := httptest.NewRequest("GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if g.gotID.UserID != 5 {
		t.Errorf("gate got identity %+v, want the resolved user 5", g.gotID)
	}
	if g.gotAccess.UserID != 5 {
		t.Errorf("audit UserID = %d, want 5", g.gotAccess.UserID)
	}
}

// No credentials → anonymous fetch is allowed (public FOSS over HTTP).
func TestServeRepos_AnonymousFetchAllowed(t *testing.T) {
	srv, g, h := newTestServer(allow("/m/x.git"))
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack")
	if rr.Code != http.StatusOK || !h.called {
		t.Fatalf("anonymous fetch should serve; status=%d handoff=%v", rr.Code, h.called)
	}
	if !g.gotID.IsAnonymous() {
		t.Errorf("gate got identity %+v, want anonymous", g.gotID)
	}
}

// A present-but-unknown token is rejected (401), never silently downgraded to
// anonymous, and never reaches the gate.
func TestServeRepos_InvalidTokenUnauthorized(t *testing.T) {
	g := &fakeGate{admitFn: allow("/m/x.git")}
	h := &fakeHandoff{}
	srv := New(g, fakeAuth{}, h, discardLogger()) // empty auth → any token is unknown

	req := httptest.NewRequest("GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer bogus")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if g.admitCalls != 0 || h.called {
		t.Errorf("an invalid token must not reach gate/handoff (admit=%d handoff=%v)", g.admitCalls, h.called)
	}
}

func TestServeRepos_UnsupportedAndBadPaths(t *testing.T) {
	srv, _, _ := newTestServer(allow("x"))
	if rr := do(srv, "GET", "/repos/github.com/o/r/objects/info/packs"); rr.Code != http.StatusNotFound {
		t.Errorf("dumb endpoint status = %d, want 404", rr.Code)
	}
	if rr := do(srv, "GET", "/repos/github.com/info/refs"); rr.Code != http.StatusBadRequest {
		t.Errorf("too-short path status = %d, want 400", rr.Code)
	}
}
