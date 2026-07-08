// Package store holds persistence backends behind the core.Store seam. Mem is an
// in-memory backend used as the default until a persistent one is wired, and as
// a test double. SQLite (local) and Postgres (production "extension") backends
// live alongside it and satisfy the same interface.
package store

import (
	"context"
	"sync"

	"codeberg.org/qwc/tulli/internal/core"
)

// Mem is a thread-safe, non-persistent core.Store. Audit data is lost on restart.
type Mem struct {
	mu     sync.Mutex
	repos  map[string]int64 // upstream_url -> id
	next   int64
	events []core.Access
}

func NewMem() *Mem {
	return &Mem{repos: make(map[string]int64)}
}

func (m *Mem) UpsertRepo(_ context.Context, upstreamURL, _ string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.repos[upstreamURL]; ok {
		return id, nil
	}
	m.next++
	m.repos[upstreamURL] = m.next
	return m.next, nil
}

func (m *Mem) InsertAccessEvent(_ context.Context, a core.Access) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, a)
	return nil
}

// Events returns a copy of the recorded access events (for tests/inspection).
func (m *Mem) Events() []core.Access {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.Access(nil), m.events...)
}

// RepoCount returns how many distinct repos have been recorded.
func (m *Mem) RepoCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.repos)
}
