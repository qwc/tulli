-- +goose Up
-- Stage 4: attribute findings to the ref(s) that reach them, so the verdict
-- recompute (spec §6.7) is a plain per-(repo,ref) read rather than a git
-- containment walk. A secret commit reachable from N refs yields N finding rows
-- (one per ref) — which is correct for secrets: the blob is cloneable from every
-- ref that contains it (§6.7 reachability). repo_id is denormalized from
-- scans(repo_id) for a cheap indexed lookup.
ALTER TABLE findings ADD COLUMN repo_id BIGINT REFERENCES repos(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN ref TEXT;
CREATE INDEX idx_findings_repo_ref ON findings(repo_id, ref);

-- +goose Down
DROP INDEX IF EXISTS idx_findings_repo_ref;
ALTER TABLE findings DROP COLUMN IF EXISTS ref;
ALTER TABLE findings DROP COLUMN IF EXISTS repo_id;
