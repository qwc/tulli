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
  `TULLI_DATABASE_URL` is set, else an in-memory store. No gate/scan/identity yet.

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
| — | `TULLI_DATABASE_URL` | (unset) | Postgres DSN for the audit store; unset ⇒ in-memory (non-persistent). Migrations run automatically on start. |

## Test

```sh
go test ./...            # unit + integration
go test -race ./...      # with the race detector (single-flight is concurrency-critical)
go test -short ./...     # skip the network (real GitHub) integration test
```

- **Unit:** `internal/git` (path resolve; single-flight/cache/retry/cancel via an
  injected clone fn), `internal/core` (Admit / read-only refusal),
  `internal/httpsrv` (routing, block/error mapping) — with fakes.
- **Integration (`internal/e2e`):** wires the real git/core/httpsrv stack behind
  an `httptest` server and drives actual `git clone` — over a local `file://`
  upstream (deterministic) and, unless `-short`, a real GitHub clone.
- **Postgres (`internal/store/pg`):** boots embedded-postgres, applies the schema,
  and runs the store's queries against a real PG. Skipped in `-short`; needs a
  writable `$HOME` (download cache) and network on first run.

## Layout

```
cmd/tulli         main; wiring
internal/git      path resolve, lazy mirror (single-flight), http-backend handoff
internal/core     the hallway: Gatekeeper (Admit/FinishAudit) + seams (Mirror/Store)
internal/httpsrv  HTTP door onto the hallway
internal/store    core.Store backends: Mem (test fake) + pg/ (Postgres, sqlc)
migrations/       embedded goose schema (spec §9)
spike/stage0      throwaway proof of the CGI handoff (reference)
```
