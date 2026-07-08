package httpsrv

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeGate struct {
	admitFn     func(ctx context.Context, ref git.RepoRef, verb string) (core.Admission, error)
	admitCalls  int
	finishCalls int
	gotRef      git.RepoRef
	gotVerb     string
}

func (f *fakeGate) Admit(ctx context.Context, ref git.RepoRef, verb string) (core.Admission, error) {
	f.admitCalls++
	f.gotRef, f.gotVerb = ref, verb
	return f.admitFn(ctx, ref, verb)
}
func (f *fakeGate) FinishAudit(_ context.Context, _ int64, _ int, _ int64) { f.finishCalls++ }

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

func newTestServer(admit func(ctx context.Context, ref git.RepoRef, verb string) (core.Admission, error)) (*Server, *fakeGate, *fakeHandoff) {
	g := &fakeGate{admitFn: admit}
	h := &fakeHandoff{}
	return New(g, h, discardLogger()), g, h
}

func do(srv *Server, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func allow(path string) func(context.Context, git.RepoRef, string) (core.Admission, error) {
	return func(_ context.Context, _ git.RepoRef, verb string) (core.Admission, error) {
		return core.Admission{Allowed: true, RepoPath: path, Verb: verb}, nil
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
	srv, _, _ := newTestServer(func(context.Context, git.RepoRef, string) (core.Admission, error) {
		return core.Admission{}, io.ErrUnexpectedEOF
	})
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
}

func TestServeRepos_QuarantinedIsForbiddenWithMessage(t *testing.T) {
	srv, _, h := newTestServer(func(context.Context, git.RepoRef, string) (core.Admission, error) {
		return core.Admission{Allowed: false, BlockMsg: "QUARANTINED: secret"}, nil
	})
	rr := do(srv, "GET", "/repos/github.com/o/r/info/refs?service=git-upload-pack")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if h.called {
		t.Error("blocked request must not hand off")
	}
	if body := rr.Body.String(); body == "" || body[:12] != "QUARANTINED:" {
		t.Errorf("body = %q, want the block message", body)
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
