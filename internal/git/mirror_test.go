package git

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testMirror builds a Mirror whose clone step is the provided fake.
func testMirror(t *testing.T, cloneFn func(ctx context.Context, upstream, dst string) error) *Mirror {
	t.Helper()
	m := NewMirror(filepath.Join(t.TempDir(), "mirrors"), "file:///unused", discardLogger())
	m.cloneFn = cloneFn
	return m
}

// writeFakeBareRepo makes dst pass isBareRepo without invoking real git.
func writeFakeBareRepo(dst string) error {
	if err := os.MkdirAll(filepath.Join(dst, "objects"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dst, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
}

// The core single-flight property: N concurrent first-fetches of the same ref
// trigger exactly one clone, and all callers get the same mirror.
func TestEnsurePresent_SingleFlight(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	m := testMirror(t, func(_ context.Context, _, dst string) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started) // leader entered the clone
		}
		<-release // hold so followers pile up on the in-flight op
		return writeFakeBareRepo(dst)
	})
	ref := RepoRef{Host: "h", Path: "o/r"}

	const N = 8
	dirs := make([]string, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			dirs[i], errs[i] = m.EnsurePresent(context.Background(), ref)
		}(i)
	}

	<-started
	time.Sleep(20 * time.Millisecond) // let followers park on the in-flight op
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("cloneFn called %d times, want exactly 1 (single-flight)", got)
	}
	want := ref.MirrorDir(m.root)
	for i := 0; i < N; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d: unexpected error %v", i, errs[i])
		}
		if dirs[i] != want {
			t.Errorf("goroutine %d dir = %q, want %q", i, dirs[i], want)
		}
	}
	if !isBareRepo(want) {
		t.Errorf("mirror not present at %s", want)
	}
}

// A follower must block on the leader's clone, not start its own.
func TestEnsurePresent_FollowerWaitsForLeader(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	m := testMirror(t, func(_ context.Context, _, dst string) error {
		atomic.AddInt32(&calls, 1)
		close(started)
		<-release
		return writeFakeBareRepo(dst)
	})
	ref := RepoRef{Host: "h", Path: "o/r"}

	go m.EnsurePresent(context.Background(), ref) // leader
	<-started

	followerDone := make(chan string, 1)
	go func() {
		dir, err := m.EnsurePresent(context.Background(), ref)
		if err != nil {
			t.Errorf("follower error: %v", err)
		}
		followerDone <- dir
	}()

	select {
	case <-followerDone:
		t.Fatal("follower returned while leader still cloning — not single-flighted")
	case <-time.After(50 * time.Millisecond):
		// good: follower is parked waiting on the leader
	}

	close(release)
	select {
	case dir := <-followerDone:
		if dir != ref.MirrorDir(m.root) {
			t.Errorf("follower dir = %q, want %q", dir, ref.MirrorDir(m.root))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower did not complete after release")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("cloneFn called %d times, want 1", got)
	}
}

// A present mirror is served from cache without re-cloning.
func TestEnsurePresent_CacheHit(t *testing.T) {
	var calls int32
	m := testMirror(t, func(_ context.Context, _, dst string) error {
		atomic.AddInt32(&calls, 1)
		return writeFakeBareRepo(dst)
	})
	ref := RepoRef{Host: "h", Path: "o/r"}

	if _, err := m.EnsurePresent(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnsurePresent(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("cloneFn called %d times across 2 calls, want 1 (cache hit)", got)
	}
}

// A failed clone leaves no mirror and is retried on the next request.
func TestEnsurePresent_RetriesAfterFailure(t *testing.T) {
	var calls int32
	m := testMirror(t, func(_ context.Context, _, dst string) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return errors.New("boom")
		}
		return writeFakeBareRepo(dst)
	})
	ref := RepoRef{Host: "h", Path: "o/r"}

	if _, err := m.EnsurePresent(context.Background(), ref); err == nil {
		t.Fatal("expected error on first (failing) attempt")
	}
	if isBareRepo(ref.MirrorDir(m.root)) {
		t.Fatal("a failed clone must not leave a mirror on disk")
	}
	if _, err := m.EnsurePresent(context.Background(), ref); err != nil {
		t.Fatalf("second attempt should succeed: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("cloneFn called %d times, want 2 (retry after failure)", got)
	}
}

// A waiting follower observes context cancellation.
func TestEnsurePresent_ContextCancelWhileWaiting(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	m := testMirror(t, func(_ context.Context, _, dst string) error {
		close(started)
		<-release
		return writeFakeBareRepo(dst)
	})
	ref := RepoRef{Host: "h", Path: "o/r"}

	leaderDone := make(chan struct{})
	go func() { m.EnsurePresent(context.Background(), ref); close(leaderDone) }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	fDone := make(chan error, 1)
	go func() { _, err := m.EnsurePresent(ctx, ref); fDone <- err }()
	cancel()

	select {
	case err := <-fDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower did not observe cancellation")
	}

	close(release)
	<-leaderDone // ensure the leader finishes before TempDir cleanup
}
