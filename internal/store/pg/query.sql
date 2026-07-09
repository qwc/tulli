-- name: UpsertRepo :one
INSERT INTO repos (upstream_url, mirror_path)
VALUES ($1, $2)
ON CONFLICT (upstream_url) DO UPDATE SET mirror_path = EXCLUDED.mirror_path
RETURNING id;

-- name: InsertAccessEvent :exec
INSERT INTO access_events (repo_id, source_ip, http_status, bytes)
VALUES ($1, sqlc.narg('source_ip')::inet, $2, $3);

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
