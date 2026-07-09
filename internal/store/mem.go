// Package store holds persistence backends behind the core.Store seam. Mem is an
// in-memory backend used as the default until a persistent one is wired, and as
// a test double. SQLite (local) and Postgres (production "extension") backends
// live alongside it and satisfy the same interface.
package store

import (
	"context"
	"sort"
	"sync"

	"codeberg.org/qwc/tulli/internal/core"
)

// Mem is a thread-safe, non-persistent core.Store. Audit data is lost on restart.
type Mem struct {
	mu       sync.Mutex
	repos    map[string]int64 // upstream_url -> id
	next     int64
	events   []core.Access
	verdicts map[int64][]memVerdict // repo_id -> verdicts, newest last
}

// memVerdict mirrors a row of the verdicts table (spec §9). ref == "" is a
// repo-wide verdict (SQL NULL).
type memVerdict struct {
	ref      string
	decision string
	reason   string
}

func NewMem() *Mem {
	return &Mem{repos: make(map[string]int64), verdicts: make(map[int64][]memVerdict)}
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

// SetVerdict records a verdict, most-recent-wins (appends). A repo-wide verdict
// uses ref == "". Test/seed helper — the real writer is the scan pipeline.
func (m *Mem) SetVerdict(repoID int64, ref, decision, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verdicts[repoID] = append(m.verdicts[repoID], memVerdict{ref: ref, decision: decision, reason: reason})
}

// ResolveVerdict applies the most-specific-wins resolver (spec §6.3) over the
// recorded verdicts: the newest row per ref is current; a current repo-wide
// (ref "") QUARANTINED blocks the whole repo, and each current per-ref
// QUARANTINED is a hidden ref.
func (m *Mem) ResolveVerdict(_ context.Context, repoID int64) (core.Verdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Newest row per ref wins (iterate newest-first, keep first seen per ref).
	current := make(map[string]memVerdict)
	rows := m.verdicts[repoID]
	for i := len(rows) - 1; i >= 0; i-- {
		if _, seen := current[rows[i].ref]; !seen {
			current[rows[i].ref] = rows[i]
		}
	}

	var v core.Verdict
	for ref, row := range current {
		if row.decision != "QUARANTINED" {
			continue
		}
		if ref == "" {
			v.RepoBlocked = true
			v.Reason = row.reason
		} else {
			v.HiddenRefs = append(v.HiddenRefs, ref)
		}
	}
	sort.Strings(v.HiddenRefs) // deterministic for tests/reconcile
	return v, nil
}

// Events returns a copy of the recorded access events (for tests/inspection).
func (m *Mem) Events() []core.Access {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.Access(nil), m.events...)
}

// RepoID returns the id assigned to an upstream URL, if recorded (for tests).
func (m *Mem) RepoID(upstreamURL string) (int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.repos[upstreamURL]
	return id, ok
}

// RepoCount returns how many distinct repos have been recorded.
func (m *Mem) RepoCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.repos)
}
