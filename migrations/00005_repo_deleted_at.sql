-- +goose Up
-- #24 — repo removal via a transient tombstone. deleted_at marks a repo as
-- "removal requested": the web API sets it (recording intent, per the §4
-- single-writer model), the gate treats a tombstoned repo as inert (blocks the
-- fetch, does not re-mirror), and the mirror-owning reconciler prunes the on-disk
-- bare mirror and then hard-deletes this row (FK cascade drops the children). The
-- column exists only for the brief window between request and actual removal —
-- after the reconciler finalizes, the row is gone, so a later fetch of the same
-- URL re-mirrors from a clean slate. NULL = live.
ALTER TABLE repos ADD COLUMN deleted_at TIMESTAMPTZ;
CREATE INDEX idx_repos_deleted_at ON repos(deleted_at) WHERE deleted_at IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_repos_deleted_at;
ALTER TABLE repos DROP COLUMN deleted_at;
