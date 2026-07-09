package git

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Mirror manages bare mirrors on disk and lazily creates them on first request.
//
// The first fetch of an un-mirrored repo blocks while the clone runs (accepted
// prototype shortcut, spec §2.1/§11.2). Concurrent first-fetches of the SAME
// repo are collapsed with a single-flight: only one clone runs, the rest wait
// for it (the gap Goblet flagged — IMPLEMENTATION.md §8).
type Mirror struct {
	root         string // <data>/mirrors
	upstreamBase string
	log          *slog.Logger

	// cloneFn performs the actual clone of upstream into an (empty) dst dir.
	// Swappable so tests can drive the single-flight logic without real git.
	cloneFn func(ctx context.Context, upstream, dst string) error

	mu       sync.Mutex
	inflight map[string]*cloneOp
}

type cloneOp struct {
	done chan struct{}
	err  error
}

func NewMirror(root, upstreamBase string, log *slog.Logger) *Mirror {
	return &Mirror{
		root:         root,
		upstreamBase: upstreamBase,
		log:          log,
		cloneFn:      gitCloneMirror,
		inflight:     make(map[string]*cloneOp),
	}
}

// UpstreamURL is the upstream this ref mirrors from (for the repo audit record).
func (m *Mirror) UpstreamURL(ref RepoRef) string { return ref.UpstreamURL(m.upstreamBase) }

// SetHiddenRefs reconciles the mirror's ref-level quarantine (spec §6.4) by
// making its uploadpack.hideRefs set match refs exactly. See SetHiddenRefs.
func (m *Mirror) SetHiddenRefs(ctx context.Context, repoPath string, refs []string) error {
	return SetHiddenRefs(ctx, repoPath, refs)
}

// EnsurePresent returns the local bare-mirror path for ref, cloning it first if
// absent. Safe for concurrent calls; duplicate first-fetches share one clone.
// created is true only for the caller whose clone materialised the mirror — the
// single fail-open-once scan trigger (followers and cache hits get false).
func (m *Mirror) EnsurePresent(ctx context.Context, ref RepoRef) (path string, created bool, err error) {
	dir := ref.MirrorDir(m.root)
	if isBareRepo(dir) {
		return dir, false, nil
	}

	m.mu.Lock()
	if op, ok := m.inflight[dir]; ok {
		// A clone for this dir is already running — wait on it (follower).
		m.mu.Unlock()
		select {
		case <-op.done:
			if op.err != nil {
				return "", false, op.err
			}
			return dir, false, nil
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
	}
	op := &cloneOp{done: make(chan struct{})}
	m.inflight[dir] = op
	m.mu.Unlock()

	err = m.clone(ctx, ref, dir)

	m.mu.Lock()
	delete(m.inflight, dir)
	m.mu.Unlock()
	op.err = err
	close(op.done)

	if err != nil {
		return "", false, err
	}
	return dir, true, nil
}

// clone materialises the mirror: it runs cloneFn into a temp dir, then
// atomically renames it into place so isBareRepo never sees a half-written repo.
func (m *Mirror) clone(ctx context.Context, ref RepoRef, dir string) error {
	upstream := ref.UpstreamURL(m.upstreamBase)
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".clone-*")
	if err != nil {
		return err
	}

	start := time.Now()
	m.log.Info("mirror clone start", "ref", ref.String(), "upstream", upstream)
	if err := m.cloneFn(ctx, upstream, tmp); err != nil {
		os.RemoveAll(tmp)
		return err
	}

	if err := os.Rename(tmp, dir); err != nil {
		os.RemoveAll(tmp)
		if isBareRepo(dir) { // lost a benign race; someone else put it there
			return nil
		}
		return err
	}
	m.log.Info("mirror clone done", "ref", ref.String(), "dur", time.Since(start).Round(time.Millisecond).String())
	return nil
}

// gitCloneMirror is the production clone: `git clone --mirror` into dst.
func gitCloneMirror(ctx context.Context, upstream, dst string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--mirror", "--quiet", upstream, dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // never prompt (public/anon)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clone %s: %w: %s", upstream, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// isBareRepo is a cheap check that dir looks like a bare git repo.
func isBareRepo(dir string) bool {
	if fi, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil || fi.IsDir() {
		return false
	}
	if fi, err := os.Stat(filepath.Join(dir, "objects")); err != nil || !fi.IsDir() {
		return false
	}
	return true
}
