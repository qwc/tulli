# tulli

A caching git proxy for public open-source repos that **mirrors, continuously
scans, and quarantines** external FOSS code — a customs house for everything your
builds pull from the WWW. (`tulli` is Finnish for *customs*.)

Motivation: Yocto/Zephyr-style builds pull thousands of upstream repos; one-time
human approval doesn't scale and misses post-approval compromise. tulli is the
enforcement point — it owns the git server, so a quarantine is one check at the
top of the fetch path.

- **Design:** [`prototype-spec-v2.md`](prototype-spec-v2.md) (read §0 first).
- **Build plan / decisions:** [`IMPLEMENTATION.md`](IMPLEMENTATION.md).

## Status

Early prototype, built in stages (see `IMPLEMENTATION.md` §5).

- **Stage 0 ✅** — Strategy A validated (`spike/stage0/`).
- **Stage 1 ✅** — walking skeleton: single read-only binary that lazily mirrors a
  public upstream on first fetch (single-flighted) and serves it via
  `git-http-backend`.
- **Stage 2 ✅** — persistence + audit: full §9 schema (goose), Postgres store
  (`pgx` + `sqlc`) recording `repos` + `access_events`. Postgres when
  `TULLI_DATABASE_URL` is set, else an in-memory store.
- **Stage 3 ✅** — the gate: a repo-wide quarantine aborts the clone with an `ERR`
  pkt-line (`remote: tulli: repo QUARANTINED — …`); a ref-level quarantine hides
  just that ref via `uploadpack.hideRefs` while the rest of the repo still clones.
- **Stage 4 ✅** — secret quarantine, end to end: the first fetch is served, then
  scanned asynchronously (gitleaks, **fail-open-once**); a HIGH secret
  retro-quarantines the affected ref(s); a fingerprint override lifts the block.
  A reconciler keeps on-disk `hideRefs` matching the DB (event-driven + a periodic
  safety sweep). No operator CLI/web yet — administration is the stage-6 web API.
- **Stage 5 ✅** — SSH transport: a second door onto the same hallway
  (`git clone ssh://…`). Blocks surface on the session's stderr (`remote: …`);
  ref-level quarantine flows through the exec'd `git upload-pack` for free.
- **Stage 6a ✅** — identity & access: an SSH public key or an HTTP token resolves
  to a user (with a role and human/robot kind) behind a pluggable provider seam
  (local DB now; LDAP/OIDC later). SSH requires a known key; HTTP fetches stay
  anonymous-friendly (a present-but-invalid token is a 401). Fetches are attributed
  to the resolved user in the audit trail. Verdicts also carry provenance — human
  quarantines live in a `manual_blocks` input table so the recompute sweep can't
  clobber them.
- **Stage 6b-core ✅** — the human-facing surface: a JSON API (`internal/web`, own
  port, off the git surface) is the single writer of human intents — block/unblock
  a ref or repo, override a finding, manage users/tokens/keys — with bearer-token
  auth and role-based access (viewer/reviewer/admin). `cmd/tullictl` is the CLI
  client. A block written through the API becomes a git-side quarantine on the next
  reconcile sweep. A browser UI (token→session login) is the next slice.

### Known limitation (Strategy A)

A **ref-level** quarantine is enforced by hiding the ref, which is *silent* to the
git client: a full clone just omits it; `git clone -b <hidden>` gets git's own
"not found". Surfacing *why* a ref is hidden needs either the sideband
success-message (Strategy B) or the web/triage UI — both deferred. A **repo-wide**
quarantine does carry its reason in-band (the `ERR` message). See spec §3.3.

## Build & run

```sh
go build -o tulli ./cmd/tulli
./tulli                     # listens on :8080, mirrors under ./data/mirrors
```

Point git at it (the transparent seam — spec §4):

```sh
git config --global \
  url."http://localhost:8080/repos/github.com/".insteadOf "https://github.com/"
git clone https://github.com/octocat/Hello-World     # fetched through tulli
```

…or address it directly:

```sh
git clone http://localhost:8080/repos/github.com/octocat/Hello-World
```

### Config

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-addr` | `TULLI_ADDR` | `:8080` | listen address |
| `-data` | `TULLI_DATA` | `./data` | mirrors live in `<data>/mirrors` |
| `-upstream-base` | `TULLI_UPSTREAM_BASE` | `https://` | upstream base; a bare scheme, or a URL prefix for `file://` test fixtures |
| `-reconcile-interval` | `TULLI_RECONCILE_INTERVAL` | `30s` | how often the reconcile safety sweep runs (catches out-of-process verdict/override writes) |
| — | `TULLI_DATABASE_URL` | (unset) | Postgres DSN for the store; unset ⇒ in-memory (non-persistent). Migrations run automatically on start. |

## Docker & the demo

`docker compose up` brings up Postgres + the proxy (the image bundles `git` and
`gitleaks`). `./demo.sh` then runs the spec §12 acceptance end to end — it needs
only `git` and `docker` on the host (gitleaks, `psql`, and Postgres all run in
containers):

```sh
./demo.sh                 # builds fixtures, brings up the stack, walks steps 1–4
docker compose down -v    # tear down
```

The demo: clones a clean repo (→ CLEAN); points a leaky tag at another repo and
watches gitleaks retro-quarantine it (fail-open-once); shows the tag withheld
while `main` still clones; then overrides the finding by fingerprint (a direct
SQL `INSERT`, standing in for the stage-6 web API) and watches the reconcile
sweep lift the block. `TULLI_RECONCILE_INTERVAL` is set to `3s` in compose so the
lift is quick.

## Test

```sh
go test ./...            # unit + integration
go test -race ./...      # with the race detector (single-flight is concurrency-critical)
go test -short ./...     # skip the network (real GitHub) integration test
```

- **Unit:** `internal/git` (path resolve; single-flight/cache/retry/cancel via an
  injected clone fn; pkt-line + hideRefs against a real bare repo), `internal/core`
  (Admit / gate / fail-open-once enqueue), `internal/verdict` (blocking-set +
  recompute), `internal/scan` (gitleaks JSON parse + worker pipeline, via an
  injected runner — the binary is not required), `internal/mirror` (reconcile +
  sweep), `internal/httpsrv` (routing, block/error mapping) — with fakes.
- **Integration (`internal/e2e`):** wires the real git/core/httpsrv stack behind
  an `httptest` server and drives actual `git clone` — over a local `file://`
  upstream (deterministic) and, unless `-short`, a real GitHub clone.
- **Postgres (`internal/store/pg`):** boots embedded-postgres, applies the schema,
  and runs the store's queries against a real PG. Skipped in `-short`; needs a
  writable `$HOME` (download cache) and network on first run.

## Layout

```
cmd/tulli         main; wiring (server + scan worker + reconciler)
internal/git      path resolve, lazy mirror (single-flight), http-backend handoff,
                  ERR pkt-line + hideRefs + ref-containment (attribution)
internal/core     the hallway: Gatekeeper (Admit/FinishAudit) + seams
internal/verdict  blocking-set rule + recompute (findings + overrides → verdict)
internal/scan     Scanner seam + gitleaks adapter + async fail-open-once worker
internal/mirror   reconciler: DB verdicts → on-disk hideRefs (event + sweep)
internal/httpsrv  HTTP door onto the hallway
internal/sshsrv   SSH door onto the hallway (x/crypto/ssh)
internal/auth     identity & access: credential → user, pluggable provider seam
internal/web      JSON API + RBAC — the human-intent writer (cmd/tullictl client)
internal/store    backends: Mem (test fake) + pg/ (Postgres, sqlc)
migrations/       embedded goose schema (spec §9)
spike/stage0      throwaway proof of the CGI handoff (reference)
```

## License

[GNU AGPL-3.0](LICENSE). tulli is a network service, so the AGPL's §13 keeps
improvements shared: anyone who runs a modified version and lets users reach it
over the network must offer them the source. Using tulli imposes no obligation;
only modifying-and-serving does.
