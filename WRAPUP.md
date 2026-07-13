# tulli — prototype wrap-up

**tulli** (Finnish, *customs*) is a caching, policy-interposing git proxy for
external open-source repos. It lazily mirrors public upstreams on first fetch,
continuously scans them for secrets and vulnerabilities, quarantines bad
repos/refs, and notifies whoever already pulled something that later turns bad.
It is **read-only** (clone/fetch only, no push), a **single Go binary**, and
serves git over both **HTTP** and **SSH**.

- Module: `codeberg.org/qwc/tulli` (local dir still `git-security-proxy`)
- Binary: `cmd/tulli`; admin CLI: `cmd/tullictl`
- License: **AGPL-3.0**
- State at wrap-up: **HEAD = `34f84ac` (stage 6d), tree clean.** Stages 0–5 +
  verdict-provenance + 6a/6b-core/6b-ui/6c/6d all committed.

---

## What's IN (built, tested, committed)

### Core proxy & enforcement
- **Transparent mirror**: URL is the trigger — `…/repos/github.com/owner/repo`,
  1:1 with upstream, lazy `git clone --mirror` on first fetch. Point a fetcher at
  it with `git url.insteadOf` / Yocto `PREMIRRORS` — no manifest edits, no MITM.
- **HTTP transport** (`git http-backend` via CGI) and **SSH transport**
  (`git upload-pack`), both over one policy "hallway" (`Gatekeeper.Admit`).
- **The gate**: repo-wide block via an `ERR` pkt-line (HTTP) / stderr (SSH);
  ref-level quarantine via `uploadpack.hideRefs`. Most-specific-wins verdict
  resolver. Fail-closed on reconcile error (a bad ref never leaks).
- **Fail-open-once**: the first fetch is served while the scan runs async; if it
  turns out bad, the ref is retro-quarantined and pullers are notified.
- **Reconciler**: the DB is desired state; the reconciler makes on-disk hideRefs
  match it (event-driven + periodic safety sweep + boot). Out-of-process writes
  (web/triage) self-heal.

### Scanning (two independent lanes)
- **Fast lane — gitleaks** (secrets): walks history, commit-attributed, every hit
  is HIGH and **auto-quarantines**. Findings feed the gate.
- **Deep lane — Trivy** (SBOM/CVE): materialises a ref-tip tree (`git archive`),
  scans it, writes `vulnerabilities`/`components`/`vuln_matches`, opens a PENDING
  `triage` row per match. **CVEs never auto-block** — they go to triage.

### Human decisions (verdict provenance)
- **Manual blocks** are an input table (append-only); verdicts stay 100% derived
  by a single writer (`Recompute`), so the sweep can't clobber human intent.
- **Overrides** (VEX-style waivers) subtract findings from the blocking set.
- **Triage** decisions: Accept / Dismiss (record only), or **Quarantine** →
  writes a manual_block that actually gates (human escalates a CVE).

### Notify (closes the founding motivation)
- On any applied quarantine (secret *or* human), the reconciler notifies whoever
  pulled the repo, resolved from the audit trail by identity. Idempotent per
  verdict (the `notifications` table), so the sweep never re-notifies.
- Delivery is a **seam** (`internal/notify`); the prototype ships a log sink.
- **Known limitation**: repo-precise, not ref-precise — we know *who pulled the
  repo*, not which ref (no upload-pack want-parsing yet). See TODO "ref-level
  notify".

### Identity, access & UI
- **Identity**: SSH pubkeys + HTTP tokens behind a pluggable `auth.Authenticator`
  (local DB is the first provider). SSH rejects unknown keys; HTTP fetch may be
  anonymous, invalid token → 401.
- **RBAC**: viewer < reviewer < admin.
- **Web API** (`internal/web`, own port) — the single writer of human intents
  (DB-only; reconciler applies). Bearer-token auth + bootstrap admin token.
- **Browser UI** (server-rendered, `html/template`): token→session-cookie login
  (no passwords), repo list + detail (findings, CVEs, block/override forms),
  triage queue, self-service SSH-key upload, admin user management. Sessions are
  revocable (role re-resolved every request).
- **`tullictl`**: bearer-token CLI (kubectl shape).

### Persistence & tests
- **Postgres** (pgx + sqlc + goose) is the one real backend; `internal/store.Mem`
  is the in-memory fake for fast tests.
- Test discipline: pure logic → unit tests; I/O/subprocess → integration; real
  Postgres via embedded-postgres; real git in e2e. Everything runs under `-race`.

---

## How to run

### Environment variables
| Var | Purpose | Default |
|-----|---------|---------|
| `TULLI_ADDR` | git HTTP listen addr | `:8080` |
| `TULLI_SSH_ADDR` | SSH listen addr (empty = off) | *(off)* |
| `TULLI_WEB_ADDR` | web/API listen addr (empty = off) | *(off)* |
| `TULLI_DATA` | data dir (mirrors live here) | `./data` |
| `TULLI_UPSTREAM_BASE` | `https://` or a `file:///fixtures` prefix | `https://` |
| `TULLI_DATABASE_URL` | Postgres DSN (empty = in-memory) | *(mem)* |
| `TULLI_RECONCILE_INTERVAL` | reconcile sweep period | `30s` |
| `TULLI_BOOTSTRAP_ADMIN_TOKEN` | first-admin login token | *(none)* |
| `TULLI_SESSION_SECRET` | signs session cookies (set in prod) | *(random/ephemeral)* |
| `TULLI_WEB_SECURE_COOKIES` | `true` behind TLS | `false` |

`tullictl` reads `TULLI_URL` and `TULLI_TOKEN`.

### Run the whole thing locally (no docker, in-memory store)
Needs `git` on PATH; `gitleaks` and `trivy` on PATH for real scanning
(otherwise those scans just log a "not installed" error and the rest works).

```sh
go build -o tulli ./cmd/tulli
TULLI_ADDR=:8080 TULLI_SSH_ADDR=:2222 TULLI_WEB_ADDR=:8081 \
  TULLI_DATA=./data \
  TULLI_BOOTSTRAP_ADMIN_TOKEN="demo-admin" \
  TULLI_SESSION_SECRET="$(head -c32 /dev/urandom | base64)" \
  ./tulli
```
- Browser UI: <http://localhost:8081> — sign in with `demo-admin`.
- Clone through the proxy: `git clone http://localhost:8080/repos/github.com/octocat/Hello-World`
- With Postgres, add `TULLI_DATABASE_URL=postgres://…`.

### The scripted docker demo (secret-quarantine arc)
Host needs only `git` + `docker` (with compose); gitleaks/psql/Postgres run in
containers.
```sh
./demo.sh
```
Walks: clone-clean → leaky tag quarantined by gitleaks → ref withheld while clean
refs still clone → override by fingerprint → ref clones again.

### The full testing stack (`docker compose up`)
For a browsable environment (not the scripted arc), the compose stack now wires
every surface:
```sh
docker compose up -d --build
```
- git http: <http://localhost:8080> — `git clone http://localhost:8080/repos/github.com/octocat/Hello-World`
- web UI: <http://localhost:8081> — sign in with the bootstrap admin token (`demo-admin` by default), then mint real users / upload SSH keys
- ssh: `ssh://git@localhost:2222` (register a key in the UI first — SSH rejects unknown keys)

Defaults are real `https://` upstreams, a persistent `/data` volume (mirrors +
SSH host key survive restarts) and Postgres in a named volume. Every knob is
overridable via the shell / a `.env` file. `docker compose down` keeps the
volumes; `down -v` wipes them. The Dockerfile bakes `trivy` + a pre-warmed vuln
DB, so the deep lane scans offline.

> **Still open (issue #8):** a *scripted* UI/CVE/triage walkthrough and a
> fixture repo with a known-vulnerable dependency for Trivy. The stack is wired;
> the guided demo of the web/CVE/triage flows is the remaining piece.

#### Real repos for a live demo
The scripted `demo.sh` uses synthetic fixtures for a fast, offline arc. For a
*live* demo against real upstreams (compose defaults to `https://`), these three
exercise both scanning lanes (verified: gitleaks v8.21.2 fires on the two secret
repos; NodeGoat/railsgoat ship lockfiles Trivy turns into CVEs):

```sh
# secrets → auto-quarantine (fast lane, gitleaks)
git clone http://localhost:8080/repos/github.com/trufflesecurity/test_keys   # tiny: 3 HIGH (2 aws-access-token, 1 private-key), revoked/safe
git clone http://localhost:8080/repos/github.com/Plazmaz/leaky-repo          # heavier: ~235 findings across ~40 rule types (breadth for the findings UI)

# vulnerable dependencies → triage queue (deep lane, Trivy — never auto-blocks)
git clone http://localhost:8080/repos/github.com/OWASP/NodeGoat              # package-lock.json with deliberately outdated npm deps → many CVEs
```

First fetch fans out to both lanes automatically. Notes: real secret repos carry
the secrets *on the default branch*, so you get whole-repo/default-branch
quarantine — the "clean main + one hidden evil ref" shape is what the synthetic
`demo.sh` fixture demonstrates instead. CVEs land in the **Triage** tab a bit
after the clone (deep lane); secrets quarantine near-immediately. `OWASP/railsgoat`
(`Gemfile.lock`, Ruby) is a good alternate CVE target.

### Tests
```sh
go test ./...                 # full suite (real Postgres via embedded-postgres)
go test -short ./...          # fast: skips Postgres + real-GitHub e2e
go test -race -short ./...    # concurrency
```
Sandbox notes (from the dev env): the module cache is read-only so deps are
**vendored** (`go build`/`go test` "just work"); real-PG tests need a writable
`HOME` for embedded-postgres; `gitleaks`/`trivy`/docker are not present in the
dev sandbox, so those paths are covered by skip-guarded / faked tests and by the
docker demo on a real host.

---

## What's still TODO

Format below is one Forgejo issue per block: an `H3` title, a labels line, and a
body with acceptance criteria. Ready to paste or to feed an automatic creator.

### Remaining stage-6 identity work

### Stage 6e — LDAP/OIDC identity provider
**Labels:** `enhancement`, `stage-6e`, `identity`
**Milestone:** stage-6

Add a directory-backed `auth.Authenticator` behind the existing seam so humans
authenticate against LDAP/OIDC instead of (or alongside) local DB tokens; map
directory groups → roles.
- [ ] LDAP provider implementing `auth.Authenticator`
- [ ] Composite provider (chain local-DB + directory)
- [ ] Group→role mapping config
- [ ] "Sign in with LDAP/OIDC" button on the login page (field already present)
- [ ] Tests against a test directory (or a fake bind)

### Stage 6f — First-class robot users
**Labels:** `enhancement`, `stage-6f`, `identity`
**Milestone:** stage-6

CI principals as `kind=robot`: token/key auth only, never interactive login,
restricted role.
- [ ] Enforce robot ⇒ no session login
- [ ] Restricted default role for robots
- [ ] `tullictl`/UI affordances to create robot users + rotate their tokens
- [ ] Tests

### Stage 6g — Full per-repo RBAC
**Labels:** `enhancement`, `stage-6g`, `rbac`
**Milestone:** stage-6

Deepen the flat viewer/reviewer/admin model into per-repo ownership + scoped
permissions (responsible-owner routing for triage).
- [ ] Repo ownership model + schema
- [ ] Scope checks on write endpoints
- [ ] Owner-routed triage/notify
- [ ] Tests

### Notify & precision

### Ref-level pull attribution (Strategy B want-parsing)
**Labels:** `enhancement`, `notify`, `transport`
**Priority:** high (it's the headline "you pulled evil@abc123" promise)

Parse the upload-pack negotiation "wants" so `access_events.ref`/`commit_sha` are
populated; notify becomes ref-precise, not just repo-precise. Also unlocks band-2
sideband "why this ref is hidden" messages to the git client.
- [ ] Drive `upload-pack` (Strategy B) instead of pure CGI handoff, or parse the
      POST body to capture wants
- [ ] Populate `access_events.ref` / `commit_sha`
- [ ] Ref-scoped recipient resolution + notice copy
- [ ] Optional: band-2 sideband notice on hidden refs
- [ ] Tests

### Real notification sinks (SMTP / webhook)
**Labels:** `enhancement`, `notify`
**Priority:** medium

Implement delivery sinks behind the existing `notify.Notifier` seam; the
prototype only logs.
- [ ] SMTP sink (config: server, from, auth)
- [ ] Webhook sink (config: URL, secret)
- [ ] Render a real payload file/URL for `notifications.payload_path`
- [ ] Notify cadence: per-finding vs digest vs threshold (§11.6)

### Security hardening (before leaving prototype)

### CSRF: per-session HMAC token
**Labels:** `security`, `web`, `hardening`
**Priority:** high (before any non-prototype deployment)

The prototype relies on `SameSite=Lax` alone. Add a per-session HMAC CSRF token in
a hidden field, verified on every state-changing route.
- [ ] Mint + embed token in forms
- [ ] Verify on POST handlers
- [ ] Tests (missing/invalid token → 403)

### Production cookie & secret checklist
**Labels:** `security`, `ops`, `hardening`
**Priority:** medium

- [ ] Require `TULLI_WEB_SECURE_COOKIES=true` behind TLS (document/enforce)
- [ ] Require an explicit `TULLI_SESSION_SECRET` in prod (warn is not enough)
- [ ] Consider DB-backed revocable session store (seam already exists)

### Demo & packaging

### Wire the web surface into the demo stack
**Labels:** `demo`, `packaging`
**Priority:** high (needed to demo 6b/6c/6d live)

`docker-compose.yml` exposes only `:8080`. Add the web UI + a scripted UI/CVE/
triage walkthrough.
- [ ] Expose `:8081`, set `TULLI_WEB_ADDR`, `TULLI_BOOTSTRAP_ADMIN_TOKEN`,
      `TULLI_SESSION_SECRET`
- [ ] Extend `demo.sh` (or add `demo-web.sh`) to: create a user, mint a token,
      show a CVE match, triage-quarantine it, show the notify log line
- [ ] Add a fixture repo with a known-vulnerable dependency for Trivy

### Verify the Trivy image on a real docker host
**Labels:** `demo`, `packaging`, `needs-verification`
**Priority:** medium

The Dockerfile bakes `trivy` v0.58.1 + a pre-warmed DB but has **not been built
in the sandbox** (no docker there).
- [ ] `docker build` succeeds; DB pre-warm step works offline at runtime
- [ ] Bump the pinned Trivy version if the asset URL/DB format changed
- [ ] A real `trivy` deep scan produces a match end-to-end

### Audit-events page in the UI
**Labels:** `enhancement`, `web`
**Priority:** low

Add a `RecentAccessEvents` query + a UI page so operators can see who pulled what.
- [ ] `RecentAccessEvents` store query (mem + pg + sqlc)
- [ ] Read-only audit page (reviewer+)

### Deferred-but-unblocked backlog (design seams already in place)

### §8.3 Demand-anchored scan floor
**Labels:** `enhancement`, `scanning`, `perf`

The worker currently scans `--all`. Add a per-repo `scan_floor` (oldest ever-
requested ref date) and scan at-or-newer only.

### §8.8 Mirror refresh scheduler
**Labels:** `enhancement`, `scanning`

Jittered nightly `git remote update` over all mirrors that triggers the on-update
pipeline; tune window/jitter, upstream backoff, refresh age-out (§11.7).

### On-timer CVE re-match (re-join without re-scan)
**Labels:** `enhancement`, `scanning`, `perf`

SBOM is immutable per tip; the vuln DB drifts. Turn the timer job into a cheap
DB re-join (SBOM ⋈ vuln-DB) instead of re-running Trivy; the diff is the
interval-notify payload (§8.5).

### Native supply-chain heuristics vs external detectors
**Labels:** `research`, `scanning`

Decide which in-house diff-heuristics are worth the FP cost vs delegating to
Socket/GuardDog/Package Analysis (the deferred malicious-code detection, §11.8).
The Deep-lane seam already accepts this.

### §11.5 Black Duck (external async scanner) contract
**Labels:** `research`, `scanning`

Validate that `Descriptor`/`ScanScope` survive contact with a licensed, async,
API-based scanner.

### Ops / project

### Repo rename + vanity import path
**Labels:** `ops`, `docs`

Rename the repo to `tulli` on push; stand up the `codeberg.org/qwc/tulli` vanity
import path (nginx `go-import` meta signpost, IMPLEMENTATION §9) when the Forgejo
instance/domain is real.

### Switch to PR + issue workflow
**Labels:** `process`

Prototype commits go straight to `main`. Post-prototype: branch-per-change, PRs,
and Forgejo issues/tickets (this file's TODOs are the seed).

---

## Where the design lives
- `prototype-spec-v2.md` — the working design (read §0 change-table first).
- `IMPLEMENTATION.md` — build order + per-stage decisions (§5 has the 6a–6d blocks).
- `prototype-spec.md` — the original v1 (superseded).
