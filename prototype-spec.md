# FOSS Repo Proxy Prototype — Implementation Spec

> **Purpose of this document.** This is a spec for a working prototype of a
> transparent-ish caching git proxy with continuous scanning and quarantine.
> It's aimed at another Claude (Claude Code) that will implement it locally.
> The goal is a working end-to-end thin slice — **not** a production system.
> Where I mark something "out of scope" or "stub," take that seriously; don't
> silently expand scope.

---

## 1. Context (why this exists)

Today, external FOSS repositories are approved one-by-one by a human reviewer
before developers may use them. This does not scale to ecosystems like Yocto
(thousands of repos per build) or Zephyr (hundreds via `west` manifests). The
process also fails to catch the risks that actually matter — repos
compromised **after** approval, transitive dependencies, newly-disclosed CVEs
in already-approved code.

The proposed replacement is **continuous monitoring with quarantine**: mirror
everything that gets pulled, scan it continuously, quarantine on findings,
notify affected users. This prototype is the thin end of that wedge.

**Non-goal of the prototype:** replacing the human process. The prototype
demonstrates the mechanism. Rollout, policy, and adoption are separate.

---

## 2. Prototype scope

### In scope

- A local service that proxies/mirrors public git repositories.
- A repository inventory with metadata (URL, first seen, last fetched, last
  scanned, verdict).
- A scanner pipeline that runs on mirror update and writes verdicts.
- A quarantine mechanism that blocks fetches of flagged repos.
- A minimal web UI showing the inventory and per-repo verdict.
- A stub notification path (log line + JSON dropped to a file, not real
  email/Slack).

### Explicitly out of scope

- Authentication / user identity mapping. Assume all clients are trusted;
  log the source IP as a stand-in for identity.
- Multi-tier logic (tier 2 / tier 3). Prototype is **tier 1 only** — pull
  through, no self-service form.
- Commit-level quarantine. Repo-granular only.
- Downstream blast-radius tracing (SBOM propagation across builds).
- Deep scans (Semgrep SAST, OSV-Scanner). Fast-lane only for the prototype.
- Manifest resolution (parsing `west.yml` / Yocto layers to pre-mirror
  sub-repos). Reactive mirroring only: mirror what's actually requested.
- High availability, backup, encryption at rest, TLS termination.
- False-positive override UI. A CLI command is enough.

If you find yourself building any of the above, **stop and note it as a
follow-up** instead.

---

## 3. Architecture

Four components, all running locally via `docker compose`:

```
┌──────────────┐   git clone    ┌────────────────┐   pull-mirror   ┌──────────┐
│  git client  │───────────────>│  Forgejo       │────────────────>│ upstream │
│              │<───────────────│  (mirror+UI)   │<────────────────│ (github) │
└──────────────┘   (via forge)  └────────────────┘                 └──────────┘
                                        │  webhook on sync
                                        ▼
                                ┌────────────────┐   verdict   ┌──────────────┐
                                │  scanner-svc   │────────────>│ verdict-db   │
                                │  (Go or Python)│             │ (Postgres)   │
                                └────────────────┘             └──────────────┘
                                        │  on finding
                                        ▼
                                ┌────────────────┐
                                │  quarantine    │  archives repo in Forgejo
                                │  action        │  writes notification stub
                                └────────────────┘
```

Client-facing URL pattern:
`http://localproxy.internal:3000/mirrors/github.com/<owner>/<repo>.git`

The `mirrors/` prefix is the Forgejo org that owns all pull-mirrors.

---

## 4. Component specs

### 4.1 Forgejo (mirror + inventory + UI)

- Use the official `codeberg.org/forgejo/forgejo` image.
- Configure a single organization `mirrors` that owns every mirrored repo.
- Repository name in Forgejo: derived from upstream URL, path-flattened.
  Example: `https://github.com/zephyrproject-rtos/hal_stm32` becomes
  `mirrors/github.com--zephyrproject-rtos--hal_stm32`.
  Chose `--` as separator because `/` isn't allowed in repo names and `_`
  collides with real repo names. Store the original URL in the repo
  description field for round-tripping.
- **Pull-mirror auto-registration:** Forgejo doesn't natively let anonymous
  clients trigger creation of a new mirror. For the prototype, expose a
  small helper endpoint on the scanner-svc: `POST /register` with
  `{"upstream_url": "..."}`. It uses the Forgejo API (admin token) to
  create the mirror if it doesn't exist, then returns the local URL. Clients
  or a wrapper script call this before cloning. **Note this compromise
  explicitly in the README** — a true transparent proxy would intercept the
  clone attempt and register on the fly; that's follow-up work.
- Webhook: configure Forgejo to POST to `scanner-svc:8080/hooks/mirror-sync`
  on every mirror-sync event.
- Admin PAT: create at startup via a small init container or manual step
  documented in the README. Store in `.env`, mount as env var.

### 4.2 scanner-svc

The core service. Written in **Go** (preferred) or **Python** (acceptable if
Go is a blocker). Justification: the scanner-svc is small, mostly HTTP + shell
out to scanners + DB writes; either language is fine, Go gets a slightly
tighter container.

Endpoints:

- `POST /register` — create a mirror in Forgejo. Body: `{upstream_url}`.
  Returns `{local_url, repo_id}`. Idempotent — if the mirror exists, return
  its info.
- `POST /hooks/mirror-sync` — Forgejo webhook. Body per Forgejo's webhook
  format. On receipt, enqueue a scan job for the affected repo.
- `GET /repos` — list all mirrored repos with verdicts. JSON.
- `GET /repos/{id}` — one repo, full history of scans and verdicts.
- `POST /repos/{id}/override` — mark a finding as false-positive, un-quarantine.
  Body: `{reason, actor}`. Writes an override record and, if the repo was
  quarantined solely due to overridden findings, un-archives it in Forgejo.
- `GET /healthz` — liveness.

Scan job worker (in-process goroutine or Python thread pool, one worker is
fine for the prototype):

1. Pull the fresh bare-repo path from Forgejo's data volume (see 4.3 for
   the shared volume arrangement).
2. Run fast-lane scanners in parallel (see 4.4).
3. Aggregate findings. Any finding of severity >= HIGH triggers quarantine.
4. Write verdict record to Postgres.
5. If quarantining: call Forgejo API to archive the repo, then write
   notification stub (see 4.5).

Concurrency: one scan at a time is fine for the prototype. Use a buffered
channel / queue with a small backlog. If the queue fills, drop new webhook
events and log a warning — do not block the webhook handler.

### 4.3 Storage layout

- **Postgres 16** for verdict-db. Container, volume-mounted for persistence.
- **Forgejo data volume** shared read-only into scanner-svc so scanners can
  read the bare repos directly without cloning through git protocol.
  Forgejo stores repos at `/data/git/repositories/<org>/<repo>.git` in its
  data volume — mount that path into scanner-svc as read-only.

Schema (see section 5 for the full DDL):

- `repos` — one row per mirrored repo.
- `scans` — one row per scan run.
- `findings` — zero-or-more rows per scan.
- `verdicts` — one row per (repo, decision-event). Current verdict is the
  most recent row per repo.
- `overrides` — one row per false-positive override.
- `notifications` — one row per notification event (for the stub).

### 4.4 Scanners (fast-lane only for prototype)

Two scanners, run in parallel per scan job:

1. **gitleaks** — secrets. Run `gitleaks detect --source=<bare-repo-path>
   --report-format=json --report-path=<tmp>`. Parse output. Any finding
   is severity HIGH.

2. **Trivy** — vulnerabilities and misconfigs in a filesystem/repo scan.
   Run `trivy fs --format=json --scanners=vuln,secret,misconfig
   <bare-repo-path>`. Parse output. Map Trivy's CRITICAL/HIGH to our HIGH;
   MEDIUM/LOW to our LOW.

Install both in the scanner-svc container (multi-stage Dockerfile). Pin
versions in the Dockerfile — don't chase `:latest`.

**Scanner interface** (internal Go interface / Python ABC):

```
type Scanner interface {
    Name() string
    Scan(ctx context.Context, repoPath string) ([]Finding, error)
}
```

Each scanner is a struct/class satisfying this interface. Keep them
independent — do not share state. Adding a new scanner later (Semgrep,
OSV-Scanner) should mean one new file and one line in a registry.

### 4.5 Quarantine action + notification stub

When a scan produces HIGH-severity findings:

1. Insert a `verdicts` row with `decision='QUARANTINED'`.
2. Call Forgejo API: `PATCH /api/v1/repos/mirrors/<repo>` with
   `{"archived": true}`. Archived repos in Forgejo are read-only but still
   listable — good for the UI, blocks writes (we're read-only anyway),
   AND makes the repo visibly flagged in Forgejo's own UI.

   ⚠️ **Verify this actually blocks `git clone`.** Forgejo's "archived"
   flag is primarily a UI/write signal. If clone still works on archived
   repos, we need a different mechanism — either remove read permissions
   for the anonymous role, or set the repo to private and drop the read
   token. Test this early in implementation and adjust; document the
   final approach in the README.
3. Insert a `notifications` row with recipient list = distinct source IPs
   from the access log for this repo over the last 30 days (see 4.6).
4. Write a JSON file to `/data/notifications/<timestamp>-<repo>.json` with
   the notification payload. Structure:

```json
{
  "event": "repo_quarantined",
  "repo": "github.com/foo/bar",
  "local_url": "http://localproxy.internal:3000/mirrors/...",
  "verdict_id": 42,
  "findings_summary": "3 HIGH secrets found by gitleaks",
  "recipients": ["10.0.0.1", "10.0.0.5"],
  "timestamp": "2026-..."
}
```

Real email/Slack integration is a follow-up. The JSON file is the
contract point.

### 4.6 Access log

Forgejo logs clones in its own access log. For the prototype, either:

- **Option A (easier):** parse Forgejo's access log periodically and load
  into an `access_events` table.
- **Option B (cleaner):** stand up a small nginx in front of Forgejo that
  logs to a shared volume in a stable JSON format.

Pick Option A for the prototype. Note it in the README as a known
limitation — nginx is the right long-term shape.

Fields to capture: `timestamp, source_ip, repo_path, http_status, bytes`.

---

## 5. Data model (Postgres DDL)

```sql
CREATE TABLE repos (
    id              BIGSERIAL PRIMARY KEY,
    upstream_url    TEXT NOT NULL UNIQUE,
    forgejo_repo    TEXT NOT NULL,          -- e.g. 'mirrors/github.com--foo--bar'
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced     TIMESTAMPTZ,
    last_scanned    TIMESTAMPTZ,
    current_verdict TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (current_verdict IN ('PENDING','CLEAN','QUARANTINED'))
);

CREATE TABLE scans (
    id              BIGSERIAL PRIMARY KEY,
    repo_id         BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    commit_sha      TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          TEXT NOT NULL
                    CHECK (status IN ('RUNNING','COMPLETE','FAILED'))
);

CREATE TABLE findings (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner         TEXT NOT NULL,          -- 'gitleaks' | 'trivy'
    severity        TEXT NOT NULL
                    CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    rule_id         TEXT,
    file_path       TEXT,
    line_number     INTEGER,
    description     TEXT,
    raw             JSONB                    -- full scanner output for this finding
);

CREATE TABLE verdicts (
    id              BIGSERIAL PRIMARY KEY,
    repo_id         BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    scan_id         BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    decision        TEXT NOT NULL
                    CHECK (decision IN ('CLEAN','QUARANTINED','OVERRIDDEN')),
    reason          TEXT,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE overrides (
    id              BIGSERIAL PRIMARY KEY,
    finding_id      BIGINT REFERENCES findings(id) ON DELETE CASCADE,
    repo_id         BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE access_events (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    source_ip       INET NOT NULL,
    repo_id         BIGINT REFERENCES repos(id) ON DELETE SET NULL,
    http_status     INTEGER NOT NULL,
    bytes           BIGINT
);
CREATE INDEX idx_access_events_repo_time ON access_events(repo_id, timestamp DESC);

CREATE TABLE notifications (
    id              BIGSERIAL PRIMARY KEY,
    verdict_id      BIGINT NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    recipients      TEXT[] NOT NULL,        -- source IPs for the prototype
    payload_path    TEXT NOT NULL,          -- path to the JSON file
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

`current_verdict` on `repos` is denormalized for query speed. Keep it in
sync inside the same transaction as verdict inserts.

---

## 6. Web UI

Bare minimum, server-rendered HTML from scanner-svc. No SPA. Three pages:

1. `/` — table of all repos: URL, first seen, last scanned, current verdict.
   Filter by verdict.
2. `/repos/{id}` — repo detail: metadata, scan history, findings grouped by
   scanner and severity, list of recent access events.
3. `/repos/{id}/quarantine-form` — a form to manually toggle
   quarantine/un-quarantine with a reason. Handy for testing.

Use Go's `html/template` or Python's Jinja2. Style with a single CSS file,
system-font stack, no framework. This is a debug UI, not a product.

For a nicer inventory browse, Forgejo's own UI at `/explore/repos` already
lists mirrored repos — link to it from the header.

---

## 7. `docker compose` layout

```yaml
services:
  forgejo:
    image: codeberg.org/forgejo/forgejo:<pin>
    volumes:
      - forgejo-data:/data
    ports: ["3000:3000", "2222:22"]

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: verdicts
      POSTGRES_USER: proxy
      POSTGRES_PASSWORD: proxy
    volumes:
      - pg-data:/var/lib/postgresql/data

  scanner-svc:
    build: ./scanner-svc
    depends_on: [forgejo, postgres]
    environment:
      FORGEJO_URL: http://forgejo:3000
      FORGEJO_TOKEN: ${FORGEJO_TOKEN}
      DB_URL: postgres://proxy:proxy@postgres/verdicts?sslmode=disable
      NOTIFICATIONS_DIR: /data/notifications
    volumes:
      - forgejo-data:/forgejo-data:ro    # bare repos, read-only
      - notifications:/data/notifications
    ports: ["8080:8080"]

volumes:
  forgejo-data:
  pg-data:
  notifications:
```

Pin every image tag. Do not use `:latest`.

---

## 8. Deliverables

The repository you produce should contain:

- `docker-compose.yml`
- `scanner-svc/` — the Go/Python service, with a Dockerfile.
- `scanner-svc/migrations/` — SQL migrations (numbered files or use a tool
  like `goose` / `alembic`).
- `scanner-svc/templates/` — HTML templates for the UI.
- `README.md` — how to bring it up, how to register a repo, how to see
  scans, how to trigger a manual scan, how to override a finding. Include
  a "known limitations / follow-ups" section that captures every place
  you took a shortcut.
- `demo.sh` — a script that:
   1. Registers a known-clean repo (e.g. a small utility from GitHub).
   2. Waits for scan to complete, prints verdict.
   3. Registers a known-dirty repo (a test fixture with a fake AWS key
      committed — you'll need to create this on a local scratch git repo
      served over `file://`, don't push anything sensitive-looking to
      real GitHub).
   4. Waits for scan, prints quarantine verdict.
   5. Attempts to clone the quarantined repo — should fail.
   6. Overrides the finding, re-attempts clone — should succeed.

The `demo.sh` is the acceptance test. If it runs end-to-end, the
prototype is done.

---

## 9. Implementation order (suggested)

1. `docker-compose` skeleton with Forgejo + Postgres. Get Forgejo running,
   create the `mirrors` org and an admin PAT manually. Document the manual
   steps.
2. scanner-svc skeleton: `/healthz`, `/register`, DB migrations, insert a
   row into `repos` when registering. Verify with `curl`.
3. Forgejo webhook wiring: `/hooks/mirror-sync` receives payloads. Log
   them. Verify by manually triggering a mirror sync in Forgejo UI.
4. Scan pipeline: on webhook, run gitleaks against the bare repo path,
   write scan + findings + verdict to DB. Skip Trivy for now.
5. Quarantine: on HIGH finding, call Forgejo API to archive. **Verify
   clone is actually blocked** (see 4.5 warning). Adjust mechanism if
   needed.
6. Add Trivy scanner.
7. Web UI: `/` and `/repos/{id}`.
8. Notification stub: write JSON on quarantine.
9. Access log parser: batch job, populate `access_events`.
10. `demo.sh` and README.

Stop at step 10. Do not add features beyond this.

---

## 10. Things to check with the human before proceeding

If any of these are unclear or wrong for the target environment, ask:

- Preferred language for scanner-svc (Go vs Python).
- Whether the Forgejo archive-flag actually blocks anonymous clones in
  the target Forgejo version — this is the biggest technical risk in the
  design.
- Whether the target environment has outbound internet from the Forgejo
  container (needed to reach upstream repos). If not, the whole model
  needs rethinking.
- Whether the demo-dirty repo should be a fixture in the repo, generated
  by a script, or an external URL.

Ask up front, in one message. Do not proceed on assumptions for any of
these four.

---

## 11. What "done" looks like

- `docker compose up` brings the whole stack up cleanly on a fresh machine.
- `./demo.sh` runs green end-to-end.
- The README explains every manual step and every shortcut taken.
- The `known limitations / follow-ups` section is honest and complete.

That's it. Resist the urge to keep building.
