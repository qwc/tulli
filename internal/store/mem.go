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
	"codeberg.org/qwc/tulli/internal/verdict"
)

// Mem is a thread-safe, non-persistent core.Store. Audit data is lost on restart.
type Mem struct {
	mu        sync.Mutex
	repos     map[string]int64 // upstream_url -> id
	paths     map[int64]string // repo_id -> mirror_path
	next      int64
	nextScan  int64
	events    []core.Access
	verdicts  map[int64][]memVerdict  // repo_id -> verdicts, newest last
	findings  map[int64][]memFinding  // repo_id -> findings
	overrides map[int64][]memOverride // repo_id -> overrides
}

// memVerdict mirrors a row of the verdicts table (spec §9). ref == "" is a
// repo-wide verdict (SQL NULL).
type memVerdict struct {
	ref      string
	decision string
	reason   string
}

type memFinding struct {
	ref string
	f   verdict.Finding
}

type memOverride struct {
	ref         string // "" = repo-wide
	fingerprint string
}

func NewMem() *Mem {
	return &Mem{
		repos:     make(map[string]int64),
		paths:     make(map[int64]string),
		verdicts:  make(map[int64][]memVerdict),
		findings:  make(map[int64][]memFinding),
		overrides: make(map[int64][]memOverride),
	}
}

func (m *Mem) UpsertRepo(_ context.Context, upstreamURL, mirrorPath string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.repos[upstreamURL]; ok {
		m.paths[id] = mirrorPath
		return id, nil
	}
	m.next++
	m.repos[upstreamURL] = m.next
	m.paths[m.next] = mirrorPath
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

// InsertVerdict is the real writer (scan worker / recompute); appends most-recent.
func (m *Mem) InsertVerdict(_ context.Context, repoID int64, ref, decision, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verdicts[repoID] = append(m.verdicts[repoID], memVerdict{ref: ref, decision: decision, reason: reason})
	return nil
}

// CurrentDecision returns the newest verdict decision for (repo, ref), or "".
func (m *Mem) CurrentDecision(_ context.Context, repoID int64, ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.verdicts[repoID]
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].ref == ref {
			return rows[i].decision, nil
		}
	}
	return "", nil
}

// --- Stage 4: scan results, verdict recompute inputs, reconcile inputs ---

func (m *Mem) ListRepos(_ context.Context) ([]core.RepoInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]core.RepoInfo, 0, len(m.paths))
	for id, path := range m.paths {
		out = append(out, core.RepoInfo{ID: id, MirrorPath: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Mem) InsertScan(_ context.Context, _ int64, _, _, _ string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextScan++
	return m.nextScan, nil
}

func (m *Mem) InsertFinding(_ context.Context, _, repoID int64, ref string, f verdict.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings[repoID] = append(m.findings[repoID], memFinding{ref: ref, f: f})
	return nil
}

func (m *Mem) FindingsForRef(_ context.Context, repoID int64, ref string) ([]verdict.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []verdict.Finding
	for _, mf := range m.findings[repoID] {
		if mf.ref == ref {
			out = append(out, mf.f)
		}
	}
	return out, nil
}

func (m *Mem) AffectedRefs(_ context.Context, repoID int64) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, mf := range m.findings[repoID] {
		if mf.ref != "" && !seen[mf.ref] {
			seen[mf.ref] = true
			out = append(out, mf.ref)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *Mem) OverriddenFingerprints(_ context.Context, repoID int64, ref string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, o := range m.overrides[repoID] {
		if o.ref == "" || o.ref == ref { // repo-wide or ref-scoped (spec §6.7)
			out = append(out, o.fingerprint)
		}
	}
	return out, nil
}

func (m *Mem) InsertOverride(_ context.Context, repoID int64, ref, fingerprint, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides[repoID] = append(m.overrides[repoID], memOverride{ref: ref, fingerprint: fingerprint})
	return nil
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
