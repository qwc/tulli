-- name: UpsertRepo :one
INSERT INTO repos (upstream_url, mirror_path)
VALUES ($1, $2)
ON CONFLICT (upstream_url) DO UPDATE SET mirror_path = EXCLUDED.mirror_path
RETURNING id;

-- name: InsertAccessEvent :exec
INSERT INTO access_events (repo_id, source_ip, http_status, bytes)
VALUES ($1, sqlc.narg('source_ip')::inet, $2, $3);

-- name: ListRepos :many
SELECT id, mirror_path FROM repos;

-- name: InsertScan :one
INSERT INTO scans (repo_id, scanner, scope_kind, scope_expr, status, finished_at)
VALUES ($1, $2, $3, sqlc.narg('scope_expr'), 'COMPLETE', NOW())
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
