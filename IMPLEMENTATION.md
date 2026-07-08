# Implementation Plan — `tulli` (FOSS Repo Proxy Prototype)

> **Name:** `tulli` — Finnish for *customs*. A customs house for incoming
> open-source code: mirror → hold → inspect → clear-or-quarantine → re-inspect.
> Module path `codeberg.org/qwc/tulli` (see §9).

> Companion to `prototype-spec-v2.md` (the design). This file captures the
> **first coding decisions**: stack, the core interface, process/deployment
> boundary, build order, and testing. Where the spec says *what/why*, this says
> *how we start*. Same discipline: built-now vs. deferred is explicit, and
> deferred things stay unblocked.

---

## 1. Stack (locked)

| Concern | Decision | Note |
|---|---|---|
| Language | Go, latest stable | 1.22+ `ServeMux` method+path patterns |
| Process model | **Single binary** (`cmd/tulli`) | HTTP + SSH + web + workers + scheduler as goroutines. Splittable later (§4). |
| Scope | **Read-only proxy** | serve `git-upload-pack` (fetch/clone) only — never `receive-pack`. No push, no upstream write path. Invariant. |
| HTTP | stdlib `net/http` + `net/http/cgi` | CGI drives `git http-backend` (Strategy A, spec §3.1). No web framework. |
| SSH | `golang.org/x/crypto/ssh` | in-process server, pubkey→identity (spec §3.2). |
| DB driver | `pgx/v5` | native Postgres protocol. |
| Queries | **`sqlc`** | type-safe Go generated from hand-written SQL; matches the spec's SQL-first, own-the-DDL ethos. |
| Migrations | **`goose`** | plain-SQL migrations; applies the spec §9 DDL. |
| Logging | `log/slog` | structured, stdlib. |
| Config | env + flags into a `Config` struct | no config framework. |
| Scan queue | **in-memory** channel worker pool | behind an `Enqueuer` interface so a DB-backed `scan_jobs` table can replace it later without touching callers. |

**Git plumbing is delegated to the real `git` binary** (bare repos +
`http-backend`/`upload-pack`, plus `for-each-ref`, `merge-base --is-ancestor`,
`log` for introspection). This is load-bearing (spec §0): our differentiator is
the hallway, not a git reimplementation. A third-party library is adopted only
if it reduces *adapter* boilerplate without taking over the hallway or forcing a
git reimplementation (see §7).

---

## 2. Package layout

Refines spec §2.2.

```
cmd/tulli         main; wires HTTP + SSH + web + workers + scheduler + reconciler
internal/core        the hallway: Gatekeeper (Admit/FinishAudit) + seam interfaces
internal/httpsrv     smart-HTTP handlers; cgi handoff to git http-backend
internal/sshsrv      x/crypto/ssh server; pubkey auth; exec dispatch
internal/web         self-service UI + triage console  (DB-only; see §4)
internal/git         path resolve, lazy mirror, pkt-line (ERR) helpers, introspection
internal/auth        identity: pubkey fingerprint → user, token → user
internal/gate        verdict resolver (most-specific-wins) + blocking-set recompute
internal/scan        Scanner registry + in-memory workers (fast lane)
internal/mirror      refresh scheduler + reconciler (hideRefs = DB desired state)
internal/store       sqlc-generated queries + thin wrapper
migrations/          goose .sql files (spec §9 DDL)
```

---

## 3. The hallway interface (core seam)

Two doors, one hallway (spec §2). The hallway runs the **policy** pipeline; each
transport does its own **serve** (CGI vs. exec is irreducibly transport-specific).

```go
// package core
type Admission struct {
    Allowed  bool
    Repo     Repo     // resolved + ensured-present
    RepoPath string   // bare mirror path; the transport serves from here
    BlockMsg string   // remote: message when !Allowed (spec §3.3)
    AuditID  int64    // handle to close out after serve
}

type AdmitRequest struct {
    Identity Identity // resolved by the adapter (pubkey vs token is transport-specific)
    Target   RepoRef  // parsed path: host/owner/repo (+ requested ref/service)
    SourceIP string
}

// Admit = resolve → ensure-mirrored → gate → open audit.
func (g *Gatekeeper) Admit(ctx context.Context, r AdmitRequest) (Admission, error)
func (g *Gatekeeper) FinishAudit(ctx context.Context, id int64, status int, bytes int64)
```

Seam interfaces behind `Gatekeeper` (built + tested independently):

```go
type Mirror interface {
    EnsurePresent(ctx, RepoRef) (path string, created bool, err error) // blocking lazy clone (spec §2.1/§11.2)
    Update(ctx, Repo) error                                            // git remote update (scheduler)
}
type Gate interface {
    Decide(ctx, repoID int64, ref string) (Decision, error)            // most-specific-wins (spec §6.3)
}
type Scanner interface { /* spec §8.4: Name/Descriptor/Scan */ }
type Store   interface { /* sqlc-backed */ }
```

- **HTTP adapter:** resolve identity (token) → `Admit`. Blocked → write `ERR`
  pkt-line at `info/refs` (works under Strategy A). Allowed → `cgi.Handler`
  running `git http-backend` with `GIT_PROJECT_ROOT=RepoPath`, then `FinishAudit`.
- **SSH adapter:** `PublicKeyCallback` resolves identity → `Admit`. Blocked →
  `BlockMsg` to stderr + non-zero exit. Allowed → `exec git upload-pack RepoPath`
  wired to the channel, then `FinishAudit`.

Identity is resolved **by the adapter** and passed **into** `Admit`, keeping the
hallway transport-agnostic.

---

## 4. Process boundary & the reconciler (web-as-separate-exec, unblocked)

The web UI *may later* run as a separate executable against the same DB
(different attack surface: browsers vs. CI fetchers; independent deploy). The
prototype ships it as a goroutine (`internal/web`) in the single binary — but we
enforce the boundary **now** so the split is later a `main()` + Dockerfile, not a
rewrite.

**The deciding constraint:** quarantine enforcement is `uploadpack.hideRefs`, a
**git-config write in the bare mirror on disk** (spec §6.4). Only the
mirror-owning process can do that. So:

- **DB is desired state.** Web (and any human action) writes verdict / override /
  triage rows and runs the *pure* blocking-set recompute (spec §6.7) → all DB, no
  filesystem.
- **Reconciler** (in `internal/mirror`, mirror-owning process) makes on-disk git
  config match the DB — applies/removes `hideRefs` per current verdicts. Runs on
  change *and* on boot (reconcile-all → restarts self-heal).

Rule: **`internal/web` touches only the DB and the enqueue/intent path — never
the mirror filesystem, never core functions directly.** This is what makes the
separate-exec split free.

---

## 5. Build order (de-risk the scary part first)

Each stage is a testable vertical slice.

0. ✅ **DONE (2026-07-08) — Strategy A validated.** Go `net/http` →
   `cgi.Handler` → `git http-backend` over a hand-placed bare repo: real
   `git clone` succeeds, cloned tip SHA == origin, full smart-HTTP
   (`GET info/refs` → `POST git-upload-pack`) flows through the Go handler. See
   `spike/stage0/` (`./run.sh` reproduces). Go 1.26 / git 2.54.
1. ✅ **DONE (2026-07-08).** Walking skeleton: path resolve (`internal/git`
   `RepoRef`/`ParseRequest`) + lazy single-flight `Mirror.EnsurePresent` + CGI
   handoff, wired through `core.Gatekeeper.Admit` and the `httpsrv` door. A real
   `git clone http://proxy/repos/github.com/octocat/Hello-World` works
   end-to-end; concurrent first-fetches collapse to one clone; push refused
   (read-only); unit tests for the path parser. No gate/scan/identity/store yet.
2. **Postgres + goose + sqlc.** `repos`, `access_events` → audit the clone.
3. **Gate + block message.** Manually-inserted quarantine verdict → `ERR`
   pkt-line blocks; clean ref still serves. Core of the §12 demo.
4. **gitleaks worker + fail-open-once + retro-quarantine + reconciler.** Full
   secret-quarantine flow (§12 steps 1–4). Reconciler applies `hideRefs`.
5. **SSH transport** (second door, same hallway).
6. **Identity/self-service, Trivy+SBOM, triage web UI** — order TBD.

Demoable secret-quarantine flow by stage 4.

---

## 6. Testing

Discipline: pure logic gets table/unit tests; I/O-and-subprocess paths get an
integration test that drives real `git`. Seams are injectable (`Mirror.cloneFn`,
`httpsrv.Gate`/`Handoff` interfaces) so units run without git/network.

- **Unit (in place, stage 1):** `internal/git` path resolve + single-flight /
  cache / retry / context-cancel (injected clone fn); `internal/core` Admit +
  read-only refusal; `internal/httpsrv` routing + block/error mapping (fakes).
  `core`/`httpsrv` at 100% stmt coverage; run under `-race`.
- **Integration (in place, `internal/e2e`):** real git/core/httpsrv stack behind
  an `httptest` server; actual `git clone` over `file://` (deterministic) and a
  real GitHub clone (skipped in `-short`).
- **Future:** verdict resolver (most-specific-wins + blocking-set recompute,
  §6.7), `ERR` pkt-line encoding, reachability lift (`merge-base --is-ancestor`);
  `demo.sh` acceptance per spec §12; `docker compose up` = proxy + Postgres.

---

## 7. Candidate libraries — assessed, none adopted

Rubric (§1): adopt only if it cuts *adapter* boilerplate without taking the
hallway or reimplementing git.

**Caching proxies (Goblet, git-cache-proxy, git-cache) — do NOT adopt.** These
are caching/*acceleration* proxies; we are a *policy-interposition* proxy — near
opposite goals. A cache's purpose is faithful pass-through (be invisible, just
faster); ours is to withhold refs (`hideRefs`), inject `ERR` pkt-lines, and
quarantine. Two structural conflicts:
- Object/demand-level caching does not give us a **vanilla bare mirror** to run
  `git config uploadpack.hideRefs` against and reconcile — that's our enforcement
  primitive (§4, spec §6.4).
- Demand-caching may not hold full history/refs locally, but the **scanners need
  it** (gitleaks `--all`, reachability `merge-base --is-ancestor`, Trivy tips).
  Can't scan what the cache didn't fetch.
- The caching they provide we already get from `git clone --mirror` (the cheap
  part); none touch the hallway (the hard part). Net negative.

**Keep Goblet as reference reading** for two patterns we otherwise hand-wave:
upstream auth at fetch time, and **concurrent first-fetch single-flight** (§8).

**Other classes (unchanged):**
- **`go-git`** (pure-Go git) — **skip for serving.** Diverges from the shell-out
  decision the Strategy A/B + `hideRefs` + reachability design depends on;
  advanced-protocol coverage has gaps; introspection is free from the git CLI.
- **Full server frameworks** (soft-serve, gitkit-as-server, Gitea git module) —
  **misfit.** Push/hosting-oriented; reference reading, not deps.
- **Adapter-layer accelerants** — the only category worth a look:
  `sosedoff/gitkit`, `gliderlabs/ssh`. Adopt only if they don't obscure the
  `ERR`-pkt-line gate at `info/refs`. Default: stdlib, no dep.

---

## 8. Open implementation questions

- Config surface: exact env vars (DATA dir, DB DSN, listen addrs, sweep/age-out
  knobs from spec §8.3/§8.8).
- Reconciler cadence: event-driven (on verdict write) + periodic safety sweep?
- **Concurrent first-fetch (single-flight).** Spec §11.2 resolved "first fetch
  blocks," but two clients requesting the *same* un-mirrored repo simultaneously
  must not both run `git clone --mirror`. Collapse to one in-flight clone;
  followers wait on it. (Goblet is the reference, §7.) Needed by build stage 1.
- **Upstream fetch = anonymous.** Public FOSS only; private repos out of scope →
  no upstream credentials, no credential store. Rate-limit politeness
  (backoff + jitter) still applies at scale, but it is not auth.
- (carried) spec §11.5–11.8 remain design-open; not blockers for stages 0–5.

---

## 9. Module path & vanity import path

**Now:** `module codeberg.org/qwc/tulli`. Works immediately, zero infra.
`tulli` is an **application** — only internal imports (`.../tulli/internal/…`),
nobody imports our packages — so changing the module path later is a one-line
`go.mod` edit + a repo-wide import-prefix `sed`, with **zero external breakage**.
No lock-in to future-proof against; don't stand up infra before it's needed.

**Later (own Forgejo instance / domain is real): vanity import path.** Decouples
the *import path* from *where the code is hosted*, so a Codeberg → own-Forgejo
migration doesn't churn every import. Key point: nginx is a **signpost, not a
proxy** — it serves a one-line HTML pointer during *discovery*; the actual
`git clone` goes **directly** from the Go toolchain to the real repo URL.

Mechanism: `go get qwc.example/tulli` → Go requests
`https://qwc.example/tulli?go-get=1` → expects
```html
<meta name="go-import" content="qwc.example/tulli git https://codeberg.org/qwc/tulli">
```
Go reads the real repo URL from the tag and clones from there directly.

Minimal nginx (serves the pointer for the whole `/tulli` prefix; humans get a
link to the repo):
```nginx
location /tulli {
    default_type text/html;
    return 200 '<!DOCTYPE html><meta name="go-import" content="qwc.example/tulli git https://codeberg.org/qwc/tulli"><body>See <a href="https://codeberg.org/qwc/tulli">the repo</a>.';
}
```
Caveats: must be **HTTPS** (Go requires it for module fetch); the tag covers the
whole `/tulli` prefix so nested imports resolve; prefix `location /tulli` also
matches `/tulli*` — tighten with a regex if several modules share the domain.
Optional `go-source` meta tag adds pkg.go.dev source links. Public module →
`sum.golang.org` verification just works.

To adopt: pick the domain, set `module qwc.example/tulli`, `sed` the import
prefix, add the nginx block. One afternoon, whenever the instance lands.
