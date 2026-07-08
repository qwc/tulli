-- name: UpsertRepo :one
INSERT INTO repos (upstream_url, mirror_path)
VALUES ($1, $2)
ON CONFLICT (upstream_url) DO UPDATE SET mirror_path = EXCLUDED.mirror_path
RETURNING id;

-- name: InsertAccessEvent :exec
INSERT INTO access_events (repo_id, source_ip, http_status, bytes)
VALUES ($1, sqlc.narg('source_ip')::inet, $2, $3);
