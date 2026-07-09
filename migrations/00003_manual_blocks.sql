-- +goose Up
-- Stage 6 prep — verdict provenance (design Option B). A human quarantine (the
-- repo-wide "toxic" block of §6.6, or blocking a ref the scanners think is clean)
-- has no backing finding, so it cannot be re-derived by verdict.RecomputeRepo.
-- If humans wrote the verdicts table directly, the periodic reconcile sweep would
-- clobber their decision (recompute sees no findings -> CLEAN) within one
-- interval. Instead, human intent lives here as an INPUT — the mirror image of
-- overrides: overrides SUBTRACT a finding from the blocking set, a manual_block
-- ADDS a non-finding element to it. verdicts stays 100% derived with a single
-- writer (Recompute), so the sweep can never lose a human decision, and the §11.4
-- guardrail (a fingerprint waiver cannot lift a manual block) falls out for free
-- because a manual block has no fingerprint for an override to key on.
--
-- Append-only: the latest row per (repo_id, ref) is authoritative. A human blocks
-- with active = true and lifts with a later active = false row, preserving the
-- who/when/why history. ref IS NULL is a repo-wide block.
CREATE TABLE manual_blocks (
    id          BIGSERIAL PRIMARY KEY,
    repo_id     BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref         TEXT,                 -- NULL = repo-wide
    active      BOOLEAN NOT NULL,     -- latest per (repo_id, ref) wins
    reason      TEXT NOT NULL,
    actor       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_manual_blocks_repo_ref_time ON manual_blocks(repo_id, ref, created_at DESC);

-- +goose Down
DROP TABLE manual_blocks;
