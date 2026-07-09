package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"codeberg.org/qwc/tulli/internal/git"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeMirror struct {
	dir       string
	err       error
	calls     int32
	hidden    []string // last refs passed to SetHiddenRefs
	hideCalls int32
	hideErr   error
}

func (f *fakeMirror) EnsurePresent(_ context.Context, _ git.RepoRef) (string, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.dir, f.err
}
func (f *fakeMirror) UpstreamURL(ref git.RepoRef) string { return "https://" + ref.String() }
func (f *fakeMirror) SetHiddenRefs(_ context.Context, _ string, refs []string) error {
	atomic.AddInt32(&f.hideCalls, 1)
	f.hidden = refs
	return f.hideErr
}

type fakeStore struct {
	repoID   int64
	upErr    error
	upserts  int
	upstream string
	events   []Access
	insErr   error
	verdict  Verdict
	verdErr  error
}

func (f *fakeStore) UpsertRepo(_ context.Context, upstreamURL, _ string) (int64, error) {
	f.upserts++
	f.upstream = upstreamURL
	return f.repoID, f.upErr
}
func (f *fakeStore) InsertAccessEvent(_ context.Context, a Access) error {
	f.events = append(f.events, a)
	return f.insErr
}
func (f *fakeStore) ResolveVerdict(_ context.Context, _ int64) (Verdict, error) {
	return f.verdict, f.verdErr
}

func TestAdmit_UploadPackAllowedAndRecordsRepo(t *testing.T) {
	fm := &fakeMirror{dir: "/mirrors/github.com/o/r.git"}
	fs := &fakeStore{repoID: 7}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "github.com", Path: "o/r"}, git.VerbUploadPack)
	if err != nil {
		t.Fatal(err)
	}
	if !adm.Allowed || adm.RepoPath != fm.dir || adm.RepoID != 7 {
		t.Fatalf("admission = %+v", adm)
	}
	if fm.calls != 1 {
		t.Errorf("EnsurePresent calls = %d, want 1", fm.calls)
	}
	if fs.upserts != 1 || fs.upstream != "https://github.com/o/r" {
		t.Errorf("repo upsert = %d, upstream %q", fs.upserts, fs.upstream)
	}
}

func TestAdmit_ReceivePackRefused(t *testing.T) {
	fm := &fakeMirror{dir: "unused"}
	fs := &fakeStore{}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbReceivePack)
	if err != nil {
		t.Fatal(err)
	}
	if adm.Allowed {
		t.Fatal("receive-pack (push) must be refused — read-only proxy")
	}
	if fm.calls != 0 || fs.upserts != 0 {
		t.Errorf("a refused push must touch neither mirror (%d) nor store (%d)", fm.calls, fs.upserts)
	}
	if !strings.Contains(adm.BlockMsg, "read-only") {
		t.Errorf("BlockMsg = %q, want it to mention read-only", adm.BlockMsg)
	}
}

func TestAdmit_MirrorErrorPropagates(t *testing.T) {
	g := New(&fakeMirror{err: errors.New("upstream gone")}, &fakeStore{}, discardLogger())
	if _, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs); err == nil {
		t.Fatal("want mirror error propagated")
	}
}

// A store failure must not fail the fetch — we serve without an audit id.
func TestAdmit_StoreErrorStillServes(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git"}
	fs := &fakeStore{upErr: errors.New("db down")}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil {
		t.Fatalf("store error must not fail admit: %v", err)
	}
	if !adm.Allowed || adm.RepoPath != fm.dir {
		t.Fatalf("should still serve: %+v", adm)
	}
	if adm.RepoID != 0 {
		t.Errorf("RepoID = %d, want 0 when the store failed", adm.RepoID)
	}
}

func TestAdmit_RepoWideQuarantineBlocks(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git"}
	fs := &fakeStore{repoID: 7, verdict: Verdict{RepoBlocked: true, Reason: "3 HIGH secrets (gitleaks)"}}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil {
		t.Fatal(err)
	}
	if adm.Allowed {
		t.Fatal("repo-wide QUARANTINED must block")
	}
	if !strings.Contains(adm.BlockMsg, "QUARANTINED") || !strings.Contains(adm.BlockMsg, "3 HIGH secrets") {
		t.Errorf("BlockMsg = %q, want it to mention QUARANTINED and the reason", adm.BlockMsg)
	}
	if adm.RepoID != 7 {
		t.Errorf("RepoID = %d, want 7 (block still attributed for audit)", adm.RepoID)
	}
	if fm.hideCalls != 0 {
		t.Errorf("a repo-wide block should not touch hideRefs (got %d calls)", fm.hideCalls)
	}
}

func TestAdmit_RefLevelQuarantineHidesAndServes(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git"}
	fs := &fakeStore{repoID: 7, verdict: Verdict{HiddenRefs: []string{"refs/heads/evil", "refs/tags/bad"}}}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil {
		t.Fatal(err)
	}
	if !adm.Allowed || adm.RepoPath != fm.dir {
		t.Fatalf("ref-level quarantine should still serve the repo: %+v", adm)
	}
	if fm.hideCalls != 1 {
		t.Fatalf("SetHiddenRefs calls = %d, want 1", fm.hideCalls)
	}
	if len(fm.hidden) != 2 || fm.hidden[0] != "refs/heads/evil" || fm.hidden[1] != "refs/tags/bad" {
		t.Errorf("hidden refs = %v, want the two quarantined refs", fm.hidden)
	}
}

// If we cannot hide a known-bad ref, serving would leak it — fail closed.
func TestAdmit_HideRefsFailureFailsClosed(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git", hideErr: errors.New("git config broke")}
	fs := &fakeStore{repoID: 7, verdict: Verdict{HiddenRefs: []string{"refs/heads/evil"}}}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil {
		t.Fatal(err)
	}
	if adm.Allowed {
		t.Fatal("a hideRefs reconcile failure must block, not leak the ref")
	}
}

// A transient verdict-query failure fails open (availability) — logged, serves.
func TestAdmit_VerdictErrorFailsOpen(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git"}
	fs := &fakeStore{repoID: 7, verdErr: errors.New("db hiccup")}
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil {
		t.Fatalf("verdict error must not fail admit: %v", err)
	}
	if !adm.Allowed {
		t.Fatal("verdict-query failure should fail open (serve), not block")
	}
}

func TestAdmit_CleanServesWithoutHiding(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git"}
	fs := &fakeStore{repoID: 7} // zero-value Verdict = clean
	g := New(fm, fs, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil {
		t.Fatal(err)
	}
	if !adm.Allowed {
		t.Fatal("a clean repo must serve")
	}
	if fm.hideCalls != 0 {
		t.Errorf("clean repo should not reconcile hideRefs (got %d)", fm.hideCalls)
	}
}

func TestFinishAudit_RecordsEvent(t *testing.T) {
	fs := &fakeStore{}
	g := New(&fakeMirror{}, fs, discardLogger())
	g.FinishAudit(context.Background(), Access{RepoID: 7, SourceIP: "1.2.3.4", Status: 200, Bytes: 42})
	if len(fs.events) != 1 || fs.events[0].RepoID != 7 || fs.events[0].Bytes != 42 {
		t.Fatalf("events = %+v", fs.events)
	}
}

func TestFinishAudit_SkipsWhenNoRepoID(t *testing.T) {
	fs := &fakeStore{}
	g := New(&fakeMirror{}, fs, discardLogger())
	g.FinishAudit(context.Background(), Access{RepoID: 0, Status: 200})
	if len(fs.events) != 0 {
		t.Fatalf("no event should be recorded without a repo id; got %+v", fs.events)
	}
}
