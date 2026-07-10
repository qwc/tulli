-- name: UpsertRepo :one
INSERT INTO repos (upstream_url, mirror_path)
VALUES ($1, $2)
ON CONFLICT (upstream_url) DO UPDATE SET mirror_path = EXCLUDED.mirror_path
RETURNING id;

-- name: InsertAccessEvent :exec
INSERT INTO access_events (repo_id, user_id, source_ip, http_status, bytes)
VALUES ($1, sqlc.narg('user_id'), sqlc.narg('source_ip')::inet, $2, $3);

-- name: ListRepos :many
SELECT id, mirror_path FROM repos;

-- Stage 6a: identity & access (auth.Store).

-- name: InsertUser :one
INSERT INTO users (name, role, kind) VALUES ($1, $2, $3) RETURNING id;

-- name: InsertSSHKey :exec
INSERT INTO ssh_keys (user_id, fingerprint, pubkey) VALUES ($1, $2, $3);

-- name: InsertToken :exec
INSERT INTO tokens (user_id, token_hash) VALUES ($1, $2);

-- name: UserByFingerprint :one
SELECT u.id, u.name, u.role, u.kind
FROM ssh_keys k JOIN users u ON u.id = k.user_id
WHERE k.fingerprint = $1;

-- name: UserByTokenHash :one
SELECT u.id, u.name, u.role, u.kind
FROM tokens t JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1;

-- name: UserByID :one
SELECT id, name, role, kind FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT id, name, role, kind FROM users ORDER BY id;

-- name: InsertScan :one
INSERT INTO scans (repo_id, scanner, scope_kind, scope_expr, status, finished_at)
VALUES ($1, $2, $3, sqlc.narg('scope_expr'), 'COMPLETE', NOW())
RETURNING id;

-- name: InsertTreeScan :one
-- A deep-lane (TREE) scan of a ref tip: records ref + tip_sha (spec §8.5).
INSERT INTO scans (repo_id, scanner, scope_kind, ref, tip_sha, status, finished_at)
VALUES ($1, $2, 'TREE', sqlc.narg('ref'), $3, 'COMPLETE', NOW())
RETURNING id;

-- name: UpsertVulnerability :one
-- Advisory, keyed on OSV identity (source, source_id); idempotent (spec §8.6).
INSERT INTO vulnerabilities (source, source_id, aliases, kind, cvss_vector, severity, summary)
VALUES ($1, $2, $3, $4, sqlc.narg('cvss_vector'), sqlc.narg('severity'), sqlc.narg('summary'))
ON CONFLICT (source, source_id) DO UPDATE
  SET cvss_vector = EXCLUDED.cvss_vector, severity = EXCLUDED.severity, summary = EXCLUDED.summary
RETURNING id;

-- name: UpsertComponent :one
-- SBOM entry for a tip, keyed (repo, tip, purl); immutable per tip (spec §8.5).
INSERT INTO components (repo_id, ref, tip_sha, purl, scan_id)
VALUES ($1, sqlc.narg('ref'), $2, $3, $4)
ON CONFLICT (repo_id, tip_sha, purl) DO UPDATE SET scan_id = EXCLUDED.scan_id
RETURNING id;

-- name: UpsertVulnMatch :one
-- The component⋈vuln join, keyed (component, vuln); refreshes last_seen.
INSERT INTO vuln_matches (component_id, vuln_id, scan_id, scanner, tool_severity, fixed_version)
VALUES ($1, $2, $3, $4, sqlc.narg('tool_severity'), sqlc.narg('fixed_version'))
ON CONFLICT (component_id, vuln_id) DO UPDATE
  SET last_seen = NOW(), scan_id = EXCLUDED.scan_id, fixed_version = EXCLUDED.fixed_version
RETURNING id;

-- name: OpenTriageIfAbsent :exec
-- Open a PENDING triage item for a match, once. The NOT EXISTS keeps re-scans
-- from piling up duplicate rows for the same match.
INSERT INTO triage (repo_id, ref, match_id, status)
SELECT $1, sqlc.narg('ref'), $2, 'PENDING'
WHERE NOT EXISTS (SELECT 1 FROM triage WHERE match_id = $2);

-- name: VulnMatchesForRepo :many
-- Read model for the repo detail page: every CVE match with its package, advisory
-- and current triage status/id (spec §8.5, §6d). Newest first.
SELECT COALESCE(tr.id, 0) AS triage_id, c.ref, c.purl, v.source, v.source_id, v.severity, v.summary,
       m.tool_severity, m.fixed_version, COALESCE(tr.status, 'PENDING') AS triage_status
FROM vuln_matches m
JOIN components c ON c.id = m.component_id
JOIN vulnerabilities v ON v.id = m.vuln_id
LEFT JOIN triage tr ON tr.match_id = m.id
WHERE c.repo_id = $1
ORDER BY m.last_seen DESC;

-- name: ListPendingTriage :many
-- The triage queue (spec §6d): every PENDING CVE match with enough context to
-- decide and to block.
SELECT tr.id AS triage_id, tr.repo_id, r.mirror_path, tr.ref, c.purl, v.source_id, v.severity
FROM triage tr
JOIN vuln_matches m ON m.id = tr.match_id
JOIN components c ON c.id = m.component_id
JOIN vulnerabilities v ON v.id = m.vuln_id
JOIN repos r ON r.id = tr.repo_id
WHERE tr.status = 'PENDING'
ORDER BY tr.id DESC;

-- name: TriageByID :one
-- Authoritative block target for a triage decision (spec §6d).
SELECT tr.repo_id, tr.ref, v.source_id
FROM triage tr
JOIN vuln_matches m ON m.id = tr.match_id
JOIN vulnerabilities v ON v.id = m.vuln_id
WHERE tr.id = $1;

-- name: SetTriageStatus :exec
UPDATE triage SET status = $2, reviewer = $3, note = sqlc.narg('note'), decided_at = NOW()
WHERE id = $1;

-- name: RecipientsForRepo :many
-- Who to notify: the distinct authenticated users who pulled this repo (spec §6d,
-- repo-precise — ref-level pull attribution needs upload-pack want-parsing).
SELECT DISTINCT a.user_id, u.name
FROM access_events a JOIN users u ON u.id = a.user_id
WHERE a.repo_id = $1 AND a.user_id IS NOT NULL;

-- name: RecordNotificationForLatestVerdict :one
-- Idempotently record a notification against the latest verdict for (repo, ref):
-- inserts only if no notification exists for that verdict yet, so the reconciler
-- sweep never re-notifies (spec §6d). Returns the new row id (0 rows = already
-- notified).
INSERT INTO notifications (verdict_id, recipients, payload_path)
SELECT lv.id, sqlc.arg('recipients')::bigint[], sqlc.arg('payload_path')
FROM (
  SELECT id FROM verdicts
  WHERE repo_id = sqlc.arg('repo_id') AND ref IS NOT DISTINCT FROM sqlc.narg('ref') AND decision = 'QUARANTINED'
  ORDER BY decided_at DESC LIMIT 1
) lv
WHERE NOT EXISTS (SELECT 1 FROM notifications n WHERE n.verdict_id = lv.id)
RETURNING id;

-- name: InsertFinding :exec
INSERT INTO findings
    (scan_id, repo_id, ref, scanner, severity, rule_id, file_path, line_number, commit_sha, fingerprint, description)
VALUES ($1, $2, $3, $4, $5, sqlc.narg('rule_id'), sqlc.narg('file_path'),
        sqlc.narg('line_number'), sqlc.narg('commit_sha'), sqlc.narg('fingerprint'), sqlc.narg('description'));

-- name: FindingsForRef :many
SELECT scanner, severity, rule_id, file_path, line_number, commit_sha, fingerprint, description
FROM findings WHERE repo_id = $1 AND ref = $2;

-- name: AffectedRefs :many
SELECT DISTINCT ref FROM findings WHERE repo_id = $1 AND ref IS NOT NULL;

-- name: OverriddenFingerprints :many
-- Overrides apply repo-wide (ref IS NULL) or to a specific ref (spec §6.7 scope).
SELECT fingerprint FROM overrides WHERE repo_id = $1 AND (ref IS NULL OR ref = $2);

-- name: InsertOverride :exec
INSERT INTO overrides (repo_id, ref, fingerprint, reason, actor)
VALUES ($1, sqlc.narg('ref'), $2, $3, $4);

-- name: InsertManualBlock :exec
INSERT INTO manual_blocks (repo_id, ref, active, reason, actor)
VALUES ($1, sqlc.narg('ref'), $2, $3, $4);

-- name: ActiveManualBlock :one
-- Latest human block/lift for a (repo, ref); IS NOT DISTINCT FROM matches
-- NULL=NULL so a repo-wide ($2 = NULL) lookup finds the repo-wide row.
SELECT active, reason FROM manual_blocks
WHERE repo_id = $1 AND ref IS NOT DISTINCT FROM sqlc.narg('ref')
ORDER BY created_at DESC LIMIT 1;

-- name: ManualBlockRefs :many
-- Every ref (incl. NULL/repo-wide) that has any manual-block row, so recompute
-- revisits a just-lifted ref to clear its stale verdict.
SELECT DISTINCT ref FROM manual_blocks WHERE repo_id = $1;

-- name: InsertVerdict :exec
INSERT INTO verdicts (repo_id, ref, decision, reason)
VALUES ($1, sqlc.narg('ref'), $2, sqlc.narg('reason'));

-- name: CurrentDecision :one
-- The latest decision for a (repo, ref); IS NOT DISTINCT FROM matches NULL=NULL
-- so a repo-wide ($2 = NULL) lookup finds the repo-wide row.
SELECT decision FROM verdicts
WHERE repo_id = $1 AND ref IS NOT DISTINCT FROM sqlc.narg('ref')
ORDER BY decided_at DESC LIMIT 1;

-- CurrentQuarantines returns the current (most-recent-per-ref) verdicts for a
-- repo that are QUARANTINED — the enforcement inputs for the gate (spec §6.3).
-- A NULL ref is a repo-wide quarantine. The DISTINCT ON picks the latest verdict
-- per ref *before* filtering on decision, so a newer CLEAN correctly clears an
-- older QUARANTINED.
-- name: CurrentQuarantines :many
SELECT ref, reason FROM (
    SELECT DISTINCT ON (repo_id, ref) ref, decision, reason
    FROM verdicts
    WHERE repo_id = $1
    ORDER BY repo_id, ref, decided_at DESC
) cur
WHERE decision = 'QUARANTINED';
