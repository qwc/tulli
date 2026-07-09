-- +goose Up
-- Stage 6a: identity & access. A user gains a role (the minimal authorization
-- model the web API enforces in 6b) and a kind (human vs. robot/CI — a robot
-- authenticates only by key/token, never interactively). Both default so existing
-- rows and the first-provisioned users are valid; full RBAC (per-repo ownership,
-- fine-grained scopes) deepens this later without reshaping the column.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'
    CHECK (role IN ('viewer', 'reviewer', 'admin'));
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human'
    CHECK (kind IN ('human', 'robot'));

-- +goose Down
ALTER TABLE users DROP COLUMN kind;
ALTER TABLE users DROP COLUMN role;
