-- +goose Up
-- Full schema of record (prototype-spec-v2.md §9). Stage 2 uses only `repos` and
-- `access_events`; the rest is created now so later stages add rows, not tables.

CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ssh_keys (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    pubkey      TEXT NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE repos (
    id           BIGSERIAL PRIMARY KEY,
    upstream_url TEXT NOT NULL UNIQUE,
    mirror_path  TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced  TIMESTAMPTZ,
    scan_floor   TIMESTAMPTZ
);

CREATE TABLE repo_refs (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT NOT NULL,
    tip_sha      TEXT NOT NULL,
    last_synced  TIMESTAMPTZ,
    last_scanned TIMESTAMPTZ,
    UNIQUE (repo_id, ref)
);

CREATE TABLE scans (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    scanner      TEXT NOT NULL,
    scope_kind   TEXT NOT NULL CHECK (scope_kind IN ('RANGE','TREE')),
    scope_expr   TEXT,
    ref          TEXT,
    tip_sha      TEXT,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL CHECK (status IN ('RUNNING','COMPLETE','FAILED'))
);

CREATE TABLE findings (
    id           BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner      TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    rule_id      TEXT,
    file_path    TEXT,
    line_number  INTEGER,
    commit_sha   TEXT,
    fingerprint  TEXT,
    description  TEXT,
    raw          JSONB
);

CREATE TABLE verdicts (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,
    scan_id      BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    decision     TEXT NOT NULL CHECK (decision IN ('CLEAN','QUARANTINED','OVERRIDDEN')),
    reason       TEXT,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_verdicts_repo_ref_time ON verdicts(repo_id, ref, decided_at DESC);

CREATE VIEW current_verdicts AS
SELECT DISTINCT ON (repo_id, ref)
       repo_id, ref, decision, decided_at
FROM verdicts
ORDER BY repo_id, ref, decided_at DESC;

CREATE TABLE overrides (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,
    fingerprint  TEXT NOT NULL,
    vex_status   TEXT,
    reason       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE access_events (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    source_ip    INET,
    repo_id      BIGINT REFERENCES repos(id) ON DELETE SET NULL,
    ref          TEXT,
    commit_sha   TEXT,
    http_status  INTEGER,
    bytes        BIGINT
);
CREATE INDEX idx_access_repo_ref_time ON access_events(repo_id, ref, ts DESC);

CREATE TABLE notifications (
    id           BIGSERIAL PRIMARY KEY,
    verdict_id   BIGINT NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    recipients   BIGINT[] NOT NULL,
    payload_path TEXT NOT NULL,
    sent_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vulnerabilities (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    aliases      TEXT[] NOT NULL DEFAULT '{}',
    kind         TEXT NOT NULL DEFAULT 'CVE' CHECK (kind IN ('CVE','MALWARE')),
    cvss_vector  TEXT,
    severity     TEXT CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    summary      TEXT,
    refs         JSONB,
    UNIQUE (source, source_id)
);

CREATE TABLE components (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,
    tip_sha      TEXT NOT NULL,
    purl         TEXT NOT NULL,
    scan_id      BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    UNIQUE (repo_id, tip_sha, purl)
);

CREATE TABLE vuln_matches (
    id             BIGSERIAL PRIMARY KEY,
    component_id   BIGINT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    vuln_id        BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    scan_id        BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    scanner        TEXT NOT NULL,
    tool_severity  TEXT,
    fixed_version  TEXT,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component_id, vuln_id)
);
CREATE INDEX idx_vuln_matches_vuln ON vuln_matches(vuln_id);

CREATE TABLE triage (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,
    match_id     BIGINT REFERENCES vuln_matches(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'PENDING'
                   CHECK (status IN ('PENDING','QUARANTINED','ACCEPTED','DISMISSED')),
    reviewer     TEXT,
    decided_at   TIMESTAMPTZ,
    note         TEXT
);
CREATE INDEX idx_triage_status ON triage(status, repo_id);

-- +goose Down
DROP TABLE IF EXISTS triage CASCADE;
DROP TABLE IF EXISTS vuln_matches CASCADE;
DROP TABLE IF EXISTS components CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS access_events CASCADE;
DROP TABLE IF EXISTS overrides CASCADE;
DROP VIEW IF EXISTS current_verdicts CASCADE;
DROP TABLE IF EXISTS verdicts CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS scans CASCADE;
DROP TABLE IF EXISTS repo_refs CASCADE;
DROP TABLE IF EXISTS repos CASCADE;
DROP TABLE IF EXISTS tokens CASCADE;
DROP TABLE IF EXISTS ssh_keys CASCADE;
DROP TABLE IF EXISTS users CASCADE;
