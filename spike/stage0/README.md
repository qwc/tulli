# Stage-0 spike — prove Strategy A (git-http-backend CGI handoff)

Reference artifact for `IMPLEMENTATION.md` §5 stage 0. Throwaway in spirit, kept
as a runnable proof.

## Question
Can a Go `net/http` server hand a git smart-HTTP request off to the real
`git http-backend` (via `net/http/cgi`) such that a genuine `git clone`
succeeds? Strategy A (spec §3.1) — and thus the whole prototype — rests on this.

## Result — PASS (validated 2026-07-08, Go 1.26 / git 2.54, Arch Linux)
- Real `git clone` through the server checked out the repo contents.
- Integrity: cloned `HEAD` SHA == origin `refs/heads/main` SHA.
- The full negotiation reached our handler: `GET /…/info/refs?service=git-upload-pack`
  then `POST /…/git-upload-pack` — the real protocol, not a fallback.
- `info/refs` advertisement correctly framed (`# service=git-upload-pack` + caps).

## Run it
```sh
./run.sh    # self-contained: builds a fixture bare repo, serves it, clones, verifies
```

## Notes for the real implementation
- `git 2.54` uses **protocol v2** by default: a clone does a `GET info/refs`
  advertisement plus one or more `POST git-upload-pack` calls (ls-refs, fetch),
  all correctly routed. (The readiness `curl` adds one extra `GET`.)
- Here the CGI is mounted at `/` so `PATH_INFO` == request path
  (`/spike.git/info/refs`). The real `tulli` mounts under
  `/repos/{host}/{owner}/{repo}` and strips that prefix before handoff — set
  `cgi.Handler.Root` accordingly, or rewrite `PATH_INFO`.
- `GIT_HTTP_EXPORT_ALL=1` avoids needing a `git-daemon-export-ok` marker per repo.
- `git-http-backend` is located at runtime via `git --exec-path` (portable).
- Reminder of Strategy A's limit (spec §3.1/§3.3): once we hand off, git owns the
  byte stream, so the **block** message must be written as an `ERR` pkt-line at
  `info/refs` *before* handoff; success-side sideband messages need Strategy B.
