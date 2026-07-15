// Package store holds persistence backends behind the core.Store seam. Mem is an
// in-memory backend used as the default until a persistent one is wired, and as
// a test double. SQLite (local) and Postgres (production "extension") backends
// live alongside it and satisfy the same interface.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// Mem is a thread-safe, non-persistent core.Store. Audit data is lost on restart.
type Mem struct {
	mu        sync.Mutex
	repos     map[string]int64 // upstream_url -> id
	paths     map[int64]string // repo_id -> mirror_path
	deleted   map[int64]bool   // repo_id -> tombstoned (#24, removal requested)
	next      int64
	nextScan  int64
	events    []core.Access
	verdicts  map[int64][]memVerdict     // repo_id -> verdicts, newest last
	findings  map[int64][]memFinding     // repo_id -> findings
	overrides map[int64][]memOverride    // repo_id -> overrides
	blocks    map[int64][]memManualBlock // repo_id -> manual blocks, newest last

	users    map[int64]auth.Identity // user_id -> identity (role/kind/login)
	sshKeys  map[string]int64        // fingerprint -> user_id
	tokens   map[string]int64        // token_hash -> user_id
	nextUser int64

	// Deep lane (SBOM / CVE) — spec §8.5, triage/notify §6d.
	vulns         map[string]int64 // "source|source_id" -> vuln id
	vulnByID      map[int64]memVuln
	comps         map[string]int64 // "repo|tip|purl" -> component id
	compByID      map[int64]memComp
	matches       map[string]int64 // "comp|vuln" -> match id
	matchByID     map[int64]memMatch
	triageByMatch map[int64]int64     // match id -> triage id
	triageByID    map[int64]memTriage // triage id -> row
	notified      map[int64]bool      // verdict id -> already notified
	nextVuln      int64
	nextComp      int64
	nextMatch     int64
	nextTriage    int64
	nextVerdict   int64
}

type memVuln struct{ source, sourceID, severity, summary string }
type memComp struct {
	repoID    int64
	ref, purl string
}
type memMatch struct {
	compID, vulnID         int64
	toolSeverity, fixedVer string
}
type memTriage struct {
	repoID         int64
	ref, status    string
	matchID        int64
	reviewer, note string
}

// memVerdict mirrors a row of the verdicts table (spec §9). ref == "" is a
// repo-wide verdict (SQL NULL).
type memVerdict struct {
	id       int64
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
	reason      string
	actor       string
}

// memManualBlock mirrors a manual_blocks row (verdict-provenance Option B). ref
// "" is a repo-wide block; newest row per ref is the current state.
type memManualBlock struct {
	ref    string
	active bool
	reason string
}

func NewMem() *Mem {
	return &Mem{
		repos:         make(map[string]int64),
		paths:         make(map[int64]string),
		deleted:       make(map[int64]bool),
		verdicts:      make(map[int64][]memVerdict),
		findings:      make(map[int64][]memFinding),
		overrides:     make(map[int64][]memOverride),
		blocks:        make(map[int64][]memManualBlock),
		users:         make(map[int64]auth.Identity),
		sshKeys:       make(map[string]int64),
		tokens:        make(map[string]int64),
		vulns:         make(map[string]int64),
		vulnByID:      make(map[int64]memVuln),
		comps:         make(map[string]int64),
		compByID:      make(map[int64]memComp),
		matches:       make(map[string]int64),
		matchByID:     make(map[int64]memMatch),
		triageByMatch: make(map[int64]int64),
		triageByID:    make(map[int64]memTriage),
		notified:      make(map[int64]bool),
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
	m.nextVerdict++
	m.verdicts[repoID] = append(m.verdicts[repoID], memVerdict{id: m.nextVerdict, ref: ref, decision: decision, reason: reason})
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
	m.nextVerdict++
	m.verdicts[repoID] = append(m.verdicts[repoID], memVerdict{id: m.nextVerdict, ref: ref, decision: decision, reason: reason})
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
	upstream := make(map[int64]string, len(m.repos))
	for url, id := range m.repos {
		upstream[id] = url
	}
	out := make([]core.RepoInfo, 0, len(m.paths))
	for id, path := range m.paths {
		if m.deleted[id] { // tombstoned repos (#24) drop from the list immediately
			continue
		}
		out = append(out, core.RepoInfo{ID: id, UpstreamURL: upstream[id], MirrorPath: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- #24: repo removal (transient tombstone) ---

// LookupRepo resolves a repo by URL for the gate's pre-ensure tombstone check.
func (m *Mem) LookupRepo(_ context.Context, upstreamURL string) (id int64, deleted bool, found bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, found = m.repos[upstreamURL]
	if !found {
		return 0, false, false, nil
	}
	return id, m.deleted[id], true, nil
}

// MarkRepoDeleted records removal intent (web writes; reconciler prunes).
func (m *Mem) MarkRepoDeleted(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.paths[id]; ok {
		m.deleted[id] = true
	}
	return nil
}

// DeletedRepos lists tombstoned repos awaiting prune by the reconciler.
func (m *Mem) DeletedRepos(_ context.Context) ([]core.RepoInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	upstream := make(map[int64]string, len(m.repos))
	for url, id := range m.repos {
		upstream[id] = url
	}
	var out []core.RepoInfo
	for id := range m.deleted {
		if path, ok := m.paths[id]; ok {
			out = append(out, core.RepoInfo{ID: id, UpstreamURL: upstream[id], MirrorPath: path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteRepo hard-deletes a repo and its children (mem cascade mirrors the FK).
func (m *Mem) DeleteRepo(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for url, rid := range m.repos {
		if rid == id {
			delete(m.repos, url)
			break
		}
	}
	delete(m.paths, id)
	delete(m.deleted, id)
	delete(m.verdicts, id)
	delete(m.findings, id)
	delete(m.overrides, id)
	delete(m.blocks, id)
	return nil
}

func (m *Mem) RepoByID(_ context.Context, id int64) (core.RepoInfo, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, ok := m.paths[id]
	if !ok {
		return core.RepoInfo{}, false, nil
	}
	var upstream string
	for url, rid := range m.repos {
		if rid == id {
			upstream = url
			break
		}
	}
	return core.RepoInfo{ID: id, UpstreamURL: upstream, MirrorPath: path}, true, nil
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

func (m *Mem) InsertOverride(_ context.Context, repoID int64, ref, fingerprint, reason, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides[repoID] = append(m.overrides[repoID], memOverride{ref: ref, fingerprint: fingerprint, reason: reason, actor: actor})
	return nil
}

// OverridesForRepo returns every recorded waiver for a repo (all refs), with the
// human reason and actor, so the UI can annotate findings as waived (#21).
func (m *Mem) OverridesForRepo(_ context.Context, repoID int64) ([]core.Override, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]core.Override, 0, len(m.overrides[repoID]))
	for _, o := range m.overrides[repoID] {
		out = append(out, core.Override{Ref: o.ref, Fingerprint: o.fingerprint, Reason: o.reason, Actor: o.actor})
	}
	return out, nil
}

// InsertManualBlock records a human block/lift (verdict-provenance Option B),
// most-recent-wins (appends). ref "" is repo-wide. The real writer is the future
// web API; this is also the test seam.
func (m *Mem) InsertManualBlock(_ context.Context, repoID int64, ref string, active bool, reason, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks[repoID] = append(m.blocks[repoID], memManualBlock{ref: ref, active: active, reason: reason})
	return nil
}

// ActiveManualBlock returns the newest manual-block state for (repo, ref).
func (m *Mem) ActiveManualBlock(_ context.Context, repoID int64, ref string) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.blocks[repoID]
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].ref == ref {
			return rows[i].active, rows[i].reason, nil
		}
	}
	return false, "", nil
}

// ManualBlockRefs returns every ref (incl. "" for repo-wide) that has any
// manual-block row, so recompute revisits a lifted ref to clear its verdict.
func (m *Mem) ManualBlockRefs(_ context.Context, repoID int64) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, b := range m.blocks[repoID] {
		if !seen[b.ref] {
			seen[b.ref] = true
			out = append(out, b.ref)
		}
	}
	sort.Strings(out)
	return out, nil
}

// --- Stage 6a: identity & access (auth.Store) ---

// InsertUser creates a user and returns its id (seed/web writer).
func (m *Mem) InsertUser(_ context.Context, name string, role auth.Role, kind auth.Kind) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextUser++
	m.users[m.nextUser] = auth.Identity{UserID: m.nextUser, Login: name, Role: role, Kind: kind}
	return m.nextUser, nil
}

// InsertSSHKey registers an SSH public key (by fingerprint) for a user.
func (m *Mem) InsertSSHKey(_ context.Context, userID int64, fingerprint, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sshKeys[fingerprint] = userID
	return nil
}

// InsertToken registers a hashed HTTP token for a user.
func (m *Mem) InsertToken(_ context.Context, userID int64, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tokenHash] = userID
	return nil
}

func (m *Mem) UserByFingerprint(_ context.Context, fingerprint string) (auth.Identity, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid, ok := m.sshKeys[fingerprint]
	if !ok {
		return auth.Identity{}, false, nil
	}
	id, ok := m.users[uid]
	return id, ok, nil
}

func (m *Mem) UserByTokenHash(_ context.Context, tokenHash string) (auth.Identity, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid, ok := m.tokens[tokenHash]
	if !ok {
		return auth.Identity{}, false, nil
	}
	id, ok := m.users[uid]
	return id, ok, nil
}

// UserByID resolves a user id to its current identity (session re-resolve).
func (m *Mem) UserByID(_ context.Context, userID int64) (auth.Identity, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.users[userID]
	return id, ok, nil
}

// ListUsers returns all users, id-ordered (admin views).
func (m *Mem) ListUsers(_ context.Context) ([]auth.Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]auth.Identity, 0, len(m.users))
	for _, id := range m.users {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out, nil
}

// --- Stage 6c: deep lane (SBOM / CVE) ---

func (m *Mem) InsertTreeScan(_ context.Context, _ int64, _, _, _ string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextScan++
	return m.nextScan, nil
}

func (m *Mem) UpsertVulnerability(_ context.Context, source, sourceID string, _ []string, _, severity, _, summary string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := source + "|" + sourceID
	id, ok := m.vulns[key]
	if !ok {
		m.nextVuln++
		id = m.nextVuln
		m.vulns[key] = id
	}
	m.vulnByID[id] = memVuln{source: source, sourceID: sourceID, severity: severity, summary: summary}
	return id, nil
}

func (m *Mem) UpsertComponent(_ context.Context, repoID int64, ref, tip, purl string, _ int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%d|%s|%s", repoID, tip, purl)
	id, ok := m.comps[key]
	if !ok {
		m.nextComp++
		id = m.nextComp
		m.comps[key] = id
	}
	m.compByID[id] = memComp{repoID: repoID, ref: ref, purl: purl}
	return id, nil
}

func (m *Mem) UpsertVulnMatch(_ context.Context, componentID, vulnID, _ int64, _, toolSeverity, fixedVersion string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%d|%d", componentID, vulnID)
	id, ok := m.matches[key]
	if !ok {
		m.nextMatch++
		id = m.nextMatch
		m.matches[key] = id
	}
	m.matchByID[id] = memMatch{compID: componentID, vulnID: vulnID, toolSeverity: toolSeverity, fixedVer: fixedVersion}
	return id, nil
}

func (m *Mem) OpenTriage(_ context.Context, repoID int64, ref string, matchID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.triageByMatch[matchID]; ok {
		return nil // already opened
	}
	m.nextTriage++
	m.triageByMatch[matchID] = m.nextTriage
	m.triageByID[m.nextTriage] = memTriage{repoID: repoID, ref: ref, status: "PENDING", matchID: matchID}
	return nil
}

func (m *Mem) VulnMatchesForRepo(_ context.Context, repoID int64) ([]core.VulnMatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.VulnMatch
	for mid, mm := range m.matchByID {
		comp, ok := m.compByID[mm.compID]
		if !ok || comp.repoID != repoID {
			continue
		}
		v := m.vulnByID[mm.vulnID]
		status := "PENDING"
		var triageID int64
		if tid, ok := m.triageByMatch[mid]; ok {
			triageID = tid
			status = m.triageByID[tid].status
		}
		out = append(out, core.VulnMatch{
			TriageID: triageID, Ref: comp.ref, PURL: comp.purl, Source: v.source, SourceID: v.sourceID,
			Severity: v.severity, Summary: v.summary,
			ToolSeverity: mm.toolSeverity, FixedVersion: mm.fixedVer, TriageStatus: status,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourceID < out[j].SourceID })
	return out, nil
}

// --- Stage 6d: triage + notify ---

func (m *Mem) ListPendingTriage(_ context.Context) ([]core.TriageItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.TriageItem
	for tid, tr := range m.triageByID {
		if tr.status != "PENDING" {
			continue
		}
		mm := m.matchByID[tr.matchID]
		v := m.vulnByID[mm.vulnID]
		out = append(out, core.TriageItem{
			TriageID: tid, RepoID: tr.repoID, Repo: m.paths[tr.repoID],
			Ref: tr.ref, PURL: m.compByID[mm.compID].purl, SourceID: v.sourceID, Severity: v.severity,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TriageID > out[j].TriageID })
	return out, nil
}

func (m *Mem) TriageByID(_ context.Context, triageID int64) (int64, string, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tr, ok := m.triageByID[triageID]
	if !ok {
		return 0, "", "", false, nil
	}
	sourceID := m.vulnByID[m.matchByID[tr.matchID].vulnID].sourceID
	return tr.repoID, tr.ref, sourceID, true, nil
}

func (m *Mem) SetTriageStatus(_ context.Context, triageID int64, status, reviewer, note string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tr, ok := m.triageByID[triageID]; ok {
		tr.status = status
		tr.reviewer = reviewer
		tr.note = note
		m.triageByID[triageID] = tr
	}
	return nil
}

func (m *Mem) RecipientsForRepo(_ context.Context, repoID int64) ([]core.Recipient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[int64]bool{}
	var out []core.Recipient
	for _, e := range m.events {
		if e.RepoID != repoID || e.UserID == 0 || seen[e.UserID] {
			continue
		}
		seen[e.UserID] = true
		out = append(out, core.Recipient{UserID: e.UserID, Login: m.users[e.UserID].Login})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out, nil
}

func (m *Mem) RecordNotificationForLatestVerdict(_ context.Context, repoID int64, ref string, _ []int64, _ string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Newest QUARANTINED verdict row for (repo, ref) — mirrors the SQL subquery.
	var vid int64
	rows := m.verdicts[repoID]
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].ref == ref && rows[i].decision == "QUARANTINED" {
			vid = rows[i].id
			break
		}
	}
	if vid == 0 || m.notified[vid] {
		return false, nil
	}
	m.notified[vid] = true
	return true, nil
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
