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
	dir   string
	err   error
	calls int32
}

func (f *fakeMirror) EnsurePresent(_ context.Context, _ git.RepoRef) (string, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.dir, f.err
}

func TestAdmit_UploadPackAllowed(t *testing.T) {
	fm := &fakeMirror{dir: "/mirrors/h/o/r.git"}
	g := New(fm, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbUploadPack)
	if err != nil {
		t.Fatal(err)
	}
	if !adm.Allowed {
		t.Fatal("want allowed")
	}
	if adm.RepoPath != fm.dir {
		t.Errorf("RepoPath = %q, want %q", adm.RepoPath, fm.dir)
	}
	if fm.calls != 1 {
		t.Errorf("EnsurePresent calls = %d, want 1", fm.calls)
	}
}

func TestAdmit_InfoRefsAllowed(t *testing.T) {
	fm := &fakeMirror{dir: "/m/x.git"}
	g := New(fm, discardLogger())
	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs)
	if err != nil || !adm.Allowed {
		t.Fatalf("info/refs should be allowed: adm=%+v err=%v", adm, err)
	}
}

func TestAdmit_ReceivePackRefused(t *testing.T) {
	fm := &fakeMirror{dir: "unused"}
	g := New(fm, discardLogger())

	adm, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbReceivePack)
	if err != nil {
		t.Fatal(err)
	}
	if adm.Allowed {
		t.Fatal("receive-pack (push) must be refused — read-only proxy")
	}
	if fm.calls != 0 {
		t.Errorf("mirror must not be touched for a refused push (calls=%d)", fm.calls)
	}
	if !strings.Contains(adm.BlockMsg, "read-only") {
		t.Errorf("BlockMsg = %q, want it to mention read-only", adm.BlockMsg)
	}
}

func TestAdmit_MirrorErrorPropagates(t *testing.T) {
	fm := &fakeMirror{err: errors.New("upstream gone")}
	g := New(fm, discardLogger())
	if _, err := g.Admit(context.Background(), git.RepoRef{Host: "h", Path: "o/r"}, git.VerbInfoRefs); err == nil {
		t.Fatal("want mirror error propagated")
	}
}
