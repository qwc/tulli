# `tulli` — FOSS Repo Proxy Prototype — Design v2

> **Name:** `tulli` (Finnish, *customs*) — a customs house for incoming
> open-source code. Module path `codeberg.org/qwc/tulli`. See `IMPLEMENTATION.md`.

> **Status.** This document is the result of a design discussion that revises
> the original `prototype-spec.md` (referred to below as **v1**). It changes
> several load-bearing decisions in v1 — most importantly it **drops Forgejo
> from the prototype**, **removes the `/register` endpoint**, and **adds
> ref-level (branch/tag) quarantine** to the model. Where v2 contradicts v1,
> v2 wins; where v2 is silent, v1 still applies.
>
> It keeps v1's discipline: things marked "deferred" are deferred on purpose.
> Don't silently expand scope. This is still a thin end-to-end slice, not a
> production system.

---

## 0. What changed from v1, and why

| Area | v1 | v2 | Why |
|---|---|---|---|
| Git server | Forgejo | **Our Go app** (bare repos + `git http-backend` / `git upload-pack`) | Forgejo does five jobs at once and hides the one we're studying: the mirror-and-gate loop. Owning the git server also makes enforcement ours instead of depending on a flag we don't control. |
| Repo registration | `POST /register` before clone | **URL is the trigger** — first fetch lazily mirrors | A register call is not "transparent." The path already carries the upstream identity; that's enough to mirror on the fly. |
| Repo naming | `github.com--owner--repo` (flattened) | **`github.com/owner/repo`, 1:1 with the URL** | We own storage now, so the path *is* the identity. No flattening, no round-trip hack. |
| Enforcement | Forgejo `archived` flag (unverified whether it blocks clone) | **Gate in our git handler** (`ERR` pkt-line / SSH stderr; `uploadpack.hideRefs`) | The v1 #1 risk ("does archive actually block clone?") disappears — we *are* the server. |
| Quarantine granularity | Repo only (commit-level explicitly out of scope) | **Repo AND ref (branch/tag/reference)** | Repos aren't born malicious. A poisoned tag or compromised branch arrives later. Repo-granular can't express "main clean, evil quarantined." |
| Identity | Out of scope; log source IP | **First-class: SSH pubkeys + HTTP tokens, self-service key upload** | "Notify affected users" is impossible without identity. IP-as-identity was always a placeholder. |
| Scan model | One scan per mirror-sync | **Two job types (on-update + on-timer), scanner-specific** | gitleaks and Trivy live at opposite ends of the history/state axis and need different cadences (see §8). |

---

## 1. Design theses (the "why" behind the shape)

1. **The proxy is the enforcement point.** We own the git server, so a
   quarantine decision is one check at the top of the fetch path — not a
   property of some downstream tool's flag.
2. **Transparent means "don't change the developer's workflow," not "intercept
   the network."** We achieve it by configuring the *fetcher* (git config /
   Yocto mirrors), not by MITM. See §4.
3. **The URL is dumb and total.** `…/repos/<host>/<owner>/<repo>` maps 1:1 to
   `https://<host>/<owner>/<repo>`. The rewrite the client uses and the
   upstream we mirror from stay in perfect correspondence *because* nothing is
   aliased or shortened. Keep it that way.
4. **Repositories rot after approval.** Continuous, ref-aware monitoring — not
   one-time gatekeeping — is the point. The data model and scan cadence must
   reflect that from day one, even where enforcement is still coarse.
5. **Fail open once, then quarantine retroactively.** A first fetch of an
   unscanned ref is served; the scan runs async; if it's bad, we quarantine
   *that ref* and notify exactly the people it reached. This matches thesis 4
   better than fail-open-forever or fail-closed-always.

---

## 2. Architecture: a Go front-door over bare git

```
   git over HTTPS ──▶┌──────────────────────────────────────────┐
   git over SSH   ──▶│  transports (thin adapters)              │
   browser        ──▶│  httpsrv · sshsrv · web                  │
                     └───────────────────┬──────────────────────┘
                                         │ one call into…
                     ┌───────────────────▼──────────────────────┐
                     │  core "hallway" (transport-agnostic)      │
                     │  identity → resolve → ensure-mirrored →   │
                     │  gate → serve → audit                     │
                     └──────┬───────────────────────┬────────────┘
             enqueue on     │                       │ reads current verdict
             ref update     ▼                       ▼
                     ┌────────────┐            ┌────────────┐
                     │ scan       │            │ store      │
                     │ workers    │───────────▶│ Postgres   │
                     │ (registry) │            │            │
                     └────────────┘            └────────────┘
   on-timer sweep ──────▲ (Trivy re-scan of live tips)
```

**The core hallway** is where everything interesting lives. HTTP and SSH are
~150 lines of adapter each that translate their transport into one call into
the hallway:

```
identity  ← who is this?            (SSH pubkey | HTTP token)
resolve   ← which upstream repo?    (parse the path)
ensure    ← mirrored? else lazy-clone --mirror
gate      ← current verdict(repo, requested-ref) → refuse-with-message | allow
serve     ← hand bytes to git       (http-backend for HTTP, exec for SSH)
audit     ← record (identity, repo, ref, commit, ts, bytes)
```

Do **not** build "an HTTP git server" and "an SSH git server" as two things.
Two doors, one hallway.

### 2.1 Storage layout

- Bare mirrors on disk, path mirrors the URL 1:1:
  `${DATA}/mirrors/github.com/<owner>/<repo>.git`
- Created via `git clone --mirror <upstream>` on first request —
  **anonymously** (upstreams are public FOSS; private repos are out of scope, so
  there are **no upstream credentials** and no credential store). **The first
  fetch blocks while this clone runs** — for a large upstream (kernel-scale)
  that can be minutes, and the client's `git` just waits. This is an **accepted
  shortcut for the prototype** (§11.2); the async "mirroring, retry shortly"
  response is deferred.
- Refreshed via `git remote update` on a timer (see §8).
- No Forgejo, no flattening. If Forgejo returns later (§11) it is a *separate
  consumer* with its own storage — nothing reads both layouts, so divergence
  is a non-problem.

### 2.2 Suggested Go package layout

```
cmd/gitproxy         main; wires everything
internal/httpsrv     smart-HTTP handlers, handoff (Strategy A/B)
internal/sshsrv      x/crypto/ssh server, pubkey auth, exec dispatch
internal/web         self-service UI (login, upload key, verdicts)
internal/git         path resolve, lazy mirror, handoff, pkt-line helpers
internal/auth        identity: pubkey fingerprint → user, token → user
internal/gate        verdict resolver (most-specific-wins)
internal/scan        Scanner registry + workers (fast lane / deep lane)
internal/mirror      refresh + re-scan scheduler
internal/store       Postgres access
```

---

## 3. Git transports and handoff

### 3.1 HTTP (smart protocol)

Handlers:

```
GET  /repos/{host}/{owner}/{repo}/info/refs?service=git-upload-pack
POST /repos/{host}/{owner}/{repo}/git-upload-pack
```

**Handoff strategy — start simple, keep it swappable:**

- **Strategy A (build now): shell out to `git http-backend`.** Go's built-in
  `net/http/cgi.Handler` drives it. Least code, battle-tested protocol
  handling. Set `GIT_PROJECT_ROOT`, `GIT_HTTP_EXPORT_ALL=1`, `REMOTE_USER` =
  resolved identity. Downside: git owns the byte stream once you hand off, so
  you cannot inject messages into a *successful* fetch.

- **Strategy B (deferred): drive `git upload-pack --stateless-rpc` yourself.**
  You write the `info/refs` advertisement wrapper and stream upload-pack's
  stdout. More code (~a screen of pkt-line handling), but you **own the
  stream**, which is what unlocks (a) sideband success-messages and (b)
  reachability-aware want-rejection (§7). Adopt B once — you get both.

Keep the handoff behind an interface so A→B is a swap, not a rewrite.

### 3.2 SSH

Run an **in-process SSH server** (`golang.org/x/crypto/ssh`) — *not* system
`sshd` + `authorized_keys`. This is the Gitea/Forgejo model, chosen for the
same reason: pubkey→identity lookup and command dispatch live in our code.

- `PublicKeyCallback`: compute `ssh.FingerprintSHA256(key)`, look up in
  `ssh_keys` → identity. Unknown key → reject.
- Client sends exec request `git-upload-pack '/github.com/owner/repo'`.
- Parse it, run the **same hallway** (resolve → ensure → gate → serve), then
  exec `git upload-pack <path>` wired to the SSH channel.

### 3.3 Messages git shows the developer

Two distinct channels, mapped to two needs:

- **Block message (build now).** Git renders an `ERR` pkt-line as
  `remote: <msg>` and aborts. On quarantine we respond to `info/refs` with the
  advertisement content-type and a single `ERR` packet — **before** any
  handoff, so this works under Strategy A:

  ```
  remote: ERR git-proxy: repo QUARANTINED — 3 HIGH secrets (gitleaks).
          See http://proxy.internal/repos/…
  ```

  Over SSH the equivalent is: write the message to the exec session's
  **stderr** and exit non-zero (git surfaces remote stderr as `remote:`).

- **Success/info message (deferred, needs Strategy B).** The sideband (band 2,
  the channel git's own "Counting objects…" rides) lets us prepend our own
  lines to a successful fetch:

  ```
  remote: ✔ git-proxy: mirror of github.com/owner/repo, synced 5m ago
  remote: ✔ scanned 2m ago — CLEAN (gitleaks, trivy)
  ```

---

## 4. The "transparent" seam: configure the fetcher, not the manifest

We do **not** edit Zephyr `west.yml` or Yocto recipes/layers. We configure the
layer *below* them, once per CI image / dev machine.

- **Git-level (universal).** `url.<proxy>.insteadOf` rewrites any git URL:

  ```
  git config --global \
    url."http://proxy.internal/repos/github.com/".insteadOf "https://github.com/"
  ```

  Covers plain git, submodules, and **west** (west just shells out to git, so
  it inherits this — manifests untouched).

- **Yocto-native.** bitbake's `PREMIRRORS` / `SOURCE_MIRROR_URL` is the
  purpose-built "fetch from our mirror first" mechanism — a few lines in
  `local.conf`/distro config, no recipe edits. Where bitbake shells out to git,
  the global `insteadOf` catches it too (belt and suspenders).

**Invariant:** because the URL is dumb and total (thesis 3), the rewrite target
and the mirror source are always the same string transform. The moment anyone
aliases or shortens URLs, this breaks. Don't allow it.

---

## 5. Identity & self-service

Identity is first-class in v2 (v1 punted). This is **downstream** identity —
*our* users (CI / devs) pulling *through* the proxy, for audit + precise notify.
It is unrelated to upstream: upstreams are public FOSS fetched anonymously
(§2.1), so there are no upstream credentials to manage. Minimum:

- `users`, `ssh_keys` (fingerprint → user), `tokens` (hashed, for HTTPS).
- **Self-service web frontend:** session login → paste public key → we compute
  the fingerprint and store it; same page mints an HTTP access token.
- Identity flows into `access_events`, which is what makes retroactive
  notification *precise* ("you pulled `evil@abc123`, now quarantined") instead
  of "someone from this IP touched this repo."

Login mechanism for the prototype can be minimal (local accounts / a shared
dev login). OIDC/SSO is deferred.

---

## 6. Enforcement & quarantine model (repo + ref)

### 6.1 Reachability framing (why this has two difficulty tiers)

A malicious commit `C` on branch `evil`:

- **`C` stands alone** (only `evil`/a tag leads to it) — quarantining that ref
  protects everyone. Common case. **Cheap** to enforce.
- **`C` later merges into a clean ref** (e.g. `main`) — the bad objects are now
  reachable from a ref we serve as CLEAN. The real unit becomes "commits
  reachable from a bad ref but not from any clean ref." **Hard** — this is
  where commit-level lives.

v2 solves the first tier now and keeps the second unblocked.

### 6.2 The one obstacle to remove now

v1's `repos.current_verdict TEXT` (a single value per repo) **structurally
cannot** express per-ref verdicts. Remove it as the source of truth. Verdicts
become `(repo, ref)`-scoped; `ref IS NULL` means repo-wide.

### 6.3 Most-specific-wins resolver (build now, even if only repo-wide rows exist)

```
verdict(repo, requested_ref):
    1. repo-wide row (ref IS NULL) QUARANTINED?   → block whole repo
    2. else specific-ref row QUARANTINED?          → block just this ref
    3. else CLEAN / PENDING
```

One resolver serves both granularities. Ref-level later = "start inserting rows
with a ref set" — no schema migration, no gate rewrite.

### 6.4 Cheap enforcement primitive: `uploadpack.hideRefs`

For the standalone-bad-ref case, git enforces the block for us:

```
git config --add uploadpack.hideRefs refs/heads/evil   # in the bare mirror
```

- upload-pack won't advertise the ref.
- By default git **refuses a `want` for any unadvertised OID**
  (`uploadpack.allowTipSHA1InWant` / `allowReachableSHA1InWant` /
  `allowAnySHA1InWant` all default off), so a client that knows the SHA still
  gets "not our ref."
- A normal clone simply never receives the hidden ref's unique objects.

**Airtight when the bad commit stands alone; leaks only when it's reachable
from a clean ref.** That leak case is the reason for Strategy B (§6.5). Works
today under Strategy A.

### 6.5 The hard case (deferred): reachability-aware want-rejection

Blocking a bad commit reachable from a *clean* ref means rejecting specific
`want`s mid-negotiation — which requires sitting inside the upload-pack
stream, i.e. **Strategy B**. This is the *second* reason to graduate off
`http-backend` (the first being success-messages). Adopt B once, get both.
Not built now; just not precluded.

### 6.6 Who writes a QUARANTINED row: auto vs. human-in-the-loop

Not every finding should auto-quarantine. Scanners sit at different points on a
*decision-confidence* axis, and that — not severity — decides who actuates the
verdict:

- **Secrets (gitleaks HIGH)** are deterministic and low-false-positive — a live
  AWS key is a live AWS key. These **auto-quarantine** the ref (§7).
- **CVEs (Trivy / any vuln scanner)** are the *normal state of every FOSS repo*.
  A HIGH CVE in a transitive dependency is routine; auto-quarantining on it
  would block nearly every clone the proxy ever serves — it would break the
  whole value proposition. CVE findings therefore **do not auto-quarantine**.
- **Malicious-code heuristics (§8.7)** are the highest-FP of all and likewise
  **never auto-block**.

**The review queue (triage webview).** CVE and malicious-code findings for the
mirrored repos land in a web surface where itsec / the responsible owners see:
finding + severity + affected component + **blast radius** (who pulled the
affected ref, from `access_events`) + current verdict. From there a reviewer
**decides**: quarantine (repo-wide or this ref), accept-risk/dismiss (→ an
override, modelled as VEX, §8.6), or request re-scan. The human's decision is
what writes the `QUARANTINED` / `OVERRIDDEN` verdict row; the resolver (§6.3) is
unchanged — only *what actuates it* differs (deterministic policy for secrets, a
person for everything else).

**CISA KEV** (known-exploited) and **EPSS** (exploit probability) are **triage
aids**, not auto-actions: they sort and pre-flag the queue so "KEV — block this"
floats to the top. Policy-based auto-quarantine ("auto-block anything in KEV")
is a **deferred** accelerator — unblocked by this model, not built now.

This is the operational home of thesis 4: continuous monitoring surfaces risk;
humans adjudicate the ambiguous cases; only the unambiguous (secrets) is
automatic.

### 6.7 Lifting a block: what persists, what waives

One principle: **a block persists until its specific cause is provably gone, or a
human explicitly waives it.** New commits alone never clear it. *How* it clears
depends on the finding's attribution (§8.6) and on who decided the block.

**Secrets (Commit-attributed) — reachability, auto.** A secret is a *blob in
history*: it is retrieved on every clone as long as the introducing commit is
**reachable** from the tip, *even if a later commit deletes the file* — delete ≠
rewrite; the blob stays in fetchable history (this is why leaked secrets must be
rotated, not just deleted). So a new tip stays blocked while any triggering
commit is reachable (`git merge-base --is-ancestor C tip`). Only a history
rewrite / force-push that drops all triggering commits lifts it — the tip then
reverts to fresh PENDING + re-scan (fail-open-once). (On-update gitleaks over
`old..new` still runs regardless, to catch *new* secrets in the new commits.)

**CVE / in-tree malicious (TreeState/Component-attributed) — re-scan, human.**
These are about *what the tip's tree contains*, not history. A later commit that
bumps the dependency or deletes the malicious file makes the tip clean **even
though the introducing commit is still reachable** — so the lift test is a
**re-scan/re-match of the new tip**, not reachability. Because a human made these
blocks (§6.6), a clean re-scan does not auto-serve; it **returns the item to the
triage queue** annotated "new tip; blocking CVE-X now absent" for a one-click
lift. Human stays in the loop.

**Manual waiver (override, §9) — the blocking set.** Independently, a block can
be waived. Frame the gate as a **blocking set**: ref R is blocked iff there
exists a HIGH finding on R that is (a) still applicable at the tip (per the tests
above) and (b) not covered by an active override. Overriding a fingerprint
removes it from the set; when the set empties, R serves.
- Override scope is `(repo, ref?, fingerprint)`; `ref = NULL` waives repo-wide
  (VEX `false_positive`), a ref-scoped waiver maps to VEX `accepted` (§8.6).
- **Keep the gate O(1):** inserting an override (or recording a clean re-scan)
  triggers a **verdict recompute** for the affected refs; if the blocking set
  empties, write a fresh `CLEAN`/`OVERRIDDEN` verdict row that the
  most-specific-wins resolver (§6.3) then simply reads.
- **Guardrail:** a fingerprint override composes only against *finding-derived*
  quarantines. A manual repo-wide "this whole thing is toxic" quarantine
  (`ref IS NULL`) is lifted only by a manual un-quarantine — one trivial waiver
  must not punch through a deliberate blanket block.

Two lift paths, one resolver: fingerprint-override (secrets; auto-recompute) and
triage-decision (CVE/malicious; human `ACCEPTED`/`DISMISSED`).

---

## 7. Fail-open-once middle path

- First fetch of a ref with no verdict (`PENDING`) → **serve it**, enqueue a
  scan, record the access (with ref + commit).
- Scan runs async. If HIGH findings → quarantine the affected **ref(s)** and
  write notification stubs to exactly the identities in `access_events` for
  those refs.
- Repo-wide quarantine (`ref IS NULL`) remains available for the
  "this whole thing is toxic" case.

This is the operational realization of thesis 4/5: we don't block the first
puller, but the moment we know, we contain the blast radius precisely.

---

## 8. Scanning model

### 8.1 The two built-in scanners are fundamentally different

| | walks history? | one run yields… | attribution from | cadence |
|---|---|---|---|---|
| **gitleaks** | yes (drives `git log -p`) | every finding across a commit *range*, each stamped with its `Commit` | the **output** (`Commit` field) | **incremental**: `old..new` per sync; never re-scan old commits |
| **Trivy** | no — scans one **tree state** | one ref-tip's verdict (vuln/misconfig/secret) | the **scope you chose** (which tip you scanned) | **on a timer**, per live tip — the vuln DB drifts under unchanged code |

Key consequences:

- **gitleaks is append-only.** History is immutable; a finding on a commit is
  true forever. Scan only new commits. Use `--log-opts` to scope, e.g.
  `--log-opts="evil --not main release"` (reachability-matched to the
  quarantine scope), or `"$old..$new"` incrementally, or `--all` on first scan.
  Use the `Fingerprint` field + `--baseline-path` so re-syncs don't re-alarm,
  and key `overrides` off the fingerprint (stable) not a finding id.
- **Trivy drifts.** The same unchanged tree becomes vulnerable the day a CVE is
  disclosed. So Trivy must re-run on a timer even with no push — this is the
  mechanism that catches "newly-disclosed CVEs in already-approved code," which
  a sync-only model cannot.
- **finding → affected refs** via `git for-each-ref --contains <commit>`
  (gitleaks) or "the ref you scanned" (Trivy). Neither needs a re-run to
  attribute.

### 8.2 Two job types

```
on ref update  → gitleaks over old..new    (append findings, commit-attributed)
               → trivy over the new tip      (replace that tip's vuln verdict)
on timer       → trivy over each live tip    (catch newly-disclosed CVEs)
```

Both feed the same `findings`/`verdicts` tables and the same resolver.

### 8.3 Demand-anchored scan window (don't scan archaeology)

Big, long-lived repos (Linux kernel: ~1.3M commits, thousands of tags back to
2005) make "scan all history / all tags" both ruinously expensive and
pointless — old versions are unmaintained and nobody pulls them. So coverage is
**bounded by demand**, via a per-repo **scan floor**:

- The **floor** is the commit date of the *oldest ref anyone has ever
  requested* (`repos.scan_floor`). We scan every ref at-or-newer than the
  floor, and nothing older.
- **A request always scans the requested ref** — because we serve it. If the
  requested ref is older than the current floor, the request **lowers the
  floor** to that ref's date and backfills from the new floor up to the old
  one. You can't serve something unscanned under fail-open-once (§7).
- **"Newer" is by commit date, not version name** — tag names aren't reliably
  ordered (`v6.10`, `v6.10-rc1`, vendor tags); commit date is robust.

Mechanism:

- **gitleaks (history):** one bounded invocation covers the whole window across
  all refs — `--log-opts="--all --since=<floor>"`. Git walks every ref but
  stops at the floor date; pre-floor history is never touched. Incremental
  syncs stay `old..new` (already in-window).
- **Trivy sweep set:** ref tips with commit-date ≥ floor (in-window tags +
  `main`/`master`), **plus always the requested tip**.
- **Below the floor:** unscanned → `PENDING` → fail-open-once if requested,
  which lowers the floor and triggers a backfill.

**Tree-vs-history asymmetry:** the requested tip always gets a *tree* scan
(Trivy vuln/secret/misconfig on what we actually serve), even at the floor.
Only *history* walking is bounded by the floor — i.e. we still check what a
ref presently contains, we just don't excavate its ancient
committed-then-deleted-secret history, which is the "not fruitful" part being
cut.

Example: request kernel `v6.10` → floor = `v6.10`'s date → scan `v6.10`,
`v6.11`, … `main`; ignore `v2.x`–`v5.x` entirely. Later a real request for
`v5.15` lowers the floor and backfills `v5.15`…`v6.9`.

**Sweep age-out (configurable).** Left unchecked, the in-window sweep set grows
without bound: a repo proxied for years accumulates years of tags to re-scan
nightly forever. So a ref that hasn't been *pulled* within a **sweep-active
window** drops out of the periodic re-scan. Crucially this only removes it from
the *sweep* — the ref, its history, and its last verdict are untouched; a fresh
pull re-activates it (fail-open-once refreshes the scan on demand). So aging out
is cheap and reversible; worst case is one stale-then-refreshed verdict.

This window is a **config knob, not a fixed rule**:

- **Default:** 90 days since last pull (sensible starting point; safe because
  re-activation is automatic).
- **Admin-overridable**, globally and per-repo — a security-conservative shop
  might set it to a year or disable age-out entirely (`0` / unset = never age
  out, sweep everything above the floor forever); a cost-sensitive one might
  set 30 days.

Which *other* live branch tips (beyond `main`/`master`) get swept, and how
often the sweep runs, is still a separate knob — see open questions.

### 8.4 Scanner extensibility (keep integrations open)

v1's `Scan(ctx, repoPath) ([]Finding, error)` assumes every scanner is a
synchronous local shell-out. That holds for gitleaks/Trivy (the fast lane) but
**not** for external tools like **Black Duck**, Coverity, OSV-Scanner, Semgrep,
etc., whose integration shape varies: some are remote services (submit → poll →
collect), async, licensed/rate-limited, take minutes–hours, consume a
worktree/BOM rather than a bare path, and report in their own severity
taxonomy.

So the abstraction must carry **how a scanner is driven and what it attributes
to**, not just "run it." Proposed shape (direction, not final):

```go
type Scanner interface {
    Name() string
    Descriptor() Descriptor           // capabilities: how it's driven
    Scan(ctx context.Context, scope ScanScope) (ScanResult, error)
}

type Descriptor struct {
    Attribution Attribution   // Commit | TreeState
    Lane        Lane          // Fast | Deep
    Triggers    []Trigger     // OnUpdate | OnTimer | Manual
}

type ScanScope struct {
    RepoPath string   // bare mirror
    Ref      string   // ref being scanned      (tree-state scanners)
    Tip      string   // commit sha of the tip
    Range    string   // git revision range      (history scanners, e.g. old..new)
    Worktree string   // optional checked-out tree for tools that need one
}
```

- **Fast lane vs deep lane** get separate worker pools so a slow external scan
  can't starve gitleaks/Trivy.
- **Async external tools** block inside their own `Scan()` (submit + poll
  internally) — the deep-lane worker simply tolerates long jobs. Keep the
  interface synchronous; don't leak polling into the core.
- Each scanner maps its own severities into the common `LOW/MEDIUM/HIGH`.
- **Registration goal preserved:** adding a scanner is one new file + one line
  in the registry.

For the **prototype**, only gitleaks + Trivy (fast lane) are implemented. The
Descriptor/lane/scope machinery is built so an external adapter (Black Duck et
al.) slots in later without touching the core. **Do not** implement any
external scanner now — just don't preclude it.

### 8.5 CVE findings are a *join*, and the join is what drifts — not the tree

The gitleaks/Trivy split (§8.1) recurs *inside* the CVE domain. A CVE finding is:

```
SBOM (packages@versions this tree contains)   ⋈   vuln DB (what's known-bad today)
   immutable per tree-state — like history              drifts daily — like Trivy
```

Store the **two operands separately** and the on-timer job (§8.2) stops being a
repo re-scan and becomes a **re-join of stored SBOMs against today's
vulnerability records** — no git operation, no worktree, no walking the tree:

- **SBOM per tip** is generated *on-update* (when the tree changes), immutable
  thereafter, exactly like gitleaks history. Trivy emits it directly
  (`--format cyclonedx`).
- **Vulnerability records** are ingested/refreshed on their own cadence.
- **On timer:** re-match stored SBOMs ⋈ refreshed vuln records. The *diff* of
  that re-match is precisely the interval-notification payload — "CVE-2024-X is
  new today; it hits `openssl@3.0.1`, present in `repo/ref@tip`, pulled by these
  users." That is how we "notify at intervals without re-scanning."

**Prototype scope:** build the **data-model split** (SBOM stored separately from
vuln matches) now, so re-match-without-re-scan is not precluded. The re-join
*optimization* itself may be **deferred** — the prototype can re-run `trivy fs`
(§8.2 as written) and still populate the split tables. Lock the seam, defer the
speedup.

### 8.6 Vulnerability model & the standards to normalize on

There is no single "CVE format"; there are four layers, and conflating them is
why tool outputs look incompatible:

| Layer | Names… | Standards | We use |
|---|---|---|---|
| **Definition** | the vuln in the abstract | CVE JSON 5.x (canonical), NVD JSON (CVSS+CPE), **OSV** (FOSS, version-range/ecosystem) | **OSV** |
| **Identity** | the affected package | CPE (NVD, string-matchy) vs **PURL** (`pkg:npm/foo@1.2.3`) | **PURL** |
| **Severity** | how bad | **CVSS** vector+score (v3.1/v4.0); KEV/EPSS for exploitability | **CVSS vector** (store the string) |
| **Finding / interchange** | tool X saw vuln Y here | SARIF (generic), CycloneDX/SPDX (SBOM+vuln), **VEX** (applicability) | internal tables; *emit* CycloneDX/SARIF later |

- **OSV + PURL + CVSS is the normalization target.** Modern OSS scanners
  (Trivy, grype, osv-scanner) speak OSV/CycloneDX/SARIF natively, so this covers
  the most ground with the least loss. Each scanner maps its own severity into
  our `LOW/MEDIUM/HIGH` (§8.4); we keep the raw CVSS vector too.
- **Not every advisory is a CVE.** Black Duck emits **BDSA** (often *ahead* of
  NVD), GitHub **GHSA**, Rust **RUSTSEC**, malicious packages **MAL-** (§8.7).
  So the vuln table is keyed on a generic `(source, id)` with an **aliases**
  list cross-linking to CVE when known — OSV's own `aliases` design. Black Duck
  normalizes in without forcing a CVE that may not exist yet.
- **Overrides = VEX.** CVE suppression ("not affected", "false positive",
  "accepted risk") *is* VEX (OpenVEX / CSAF / CycloneDX-VEX). Modelling the
  `overrides` table (§9) as VEX unblocks importing upstream projects' VEX and
  exporting ours; Trivy consumes VEX natively (`--vex`). Adopt the VEX *shape*
  now; import/export is **deferred**.
- **Attribution gains a third mode.** `Descriptor.Attribution` (§8.4) becomes
  `Commit | TreeState | Component` — a CVE finding attributes to a
  `purl@version`, not a commit or a whole tree.

### 8.7 Supply-chain / malicious code — a third category

A supply-chain attack (xz-utils, event-stream, SolarWinds) is usually **not a
CVE**: it's deliberately-introduced malicious code, a typosquat, a poisoned
install script, an obfuscated payload. Two sub-cases, handled very differently:

- **Known-malicious — already standardized, reuse the OSV pipeline.** Discovered
  malicious packages are published *in OSV format* with **`MAL-` IDs** (OpenSSF
  `ossf/malicious-packages`; GitHub Advisory DB "malware" category; osv.dev).
  These flow through §8.6 unchanged — just another advisory source
  (`kind = MALWARE`), linked via aliases. Zero new model. This is the one
  category that *could* auto-quarantine; default is still route-to-review (§6.6).

- **Novel / unknown malicious code — a *detection* problem, not a lookup.** No
  definition to match and **no single standard format** for the signal, because
  detection is heuristic. What exists:
  - *Detection tools* emitting their own findings (SARIF-ish): OpenSSF
    **Package Analysis** (install sandbox, watches syscalls/network),
    **GuardDog**, **Socket**, **Semgrep** rules, OSSGadget.
  - *Provenance / integrity* standards on the **prevention** side: **SLSA**
    (build provenance), **in-toto** attestations, **Sigstore** (signing +
    transparency log), **signed commits**.

  **Our structural advantage:** we mirror and **diff every update**, so
  change-based signals are free and ahead of any external tool — a new
  `postinstall`/install script, a binary blob added under a source path (xz's
  payload hid in test fixtures), a committer/maintainer identity change, an
  obfuscated/high-entropy blob added. Supply-chain attacks trip on the *delta*,
  and the delta is exactly what the proxy sees.

  Because these detectors run against the **mirrored repo directly** (bare path
  or a checked-out worktree) and emit findings that land in the *same* store and
  triage queue, the novel case reduces to **one generic seam**: a Deep-lane
  `Scanner` (attribution `Commit`/diff or `Component`, on-update trigger,
  `ScanScope.Worktree` for tools that need a tree) whose results flow into
  `vuln_matches`/`triage` (§6.6) → always human review, never auto-block.

**Scope — this is the extension, deferred on purpose.** In-house heuristic
supply-chain detection was in the *original* motivation, but it's a layer *on
top of* the basics — mirror + gate + secrets/CVE + triage must land first. So
the prototype builds only the **generic "run a detector over the mirror and
store its results" seam** (already provided by `Scanner`/`Descriptor`/`ScanScope`,
§8.4) plus the **known-malicious OSV path** (free — it's §8.6). No concrete
heuristic and no external detector (GuardDog, Socket, Package Analysis) is
implemented now; provenance verification (SLSA / in-toto / Sigstore /
signed-commit) is likewise mentioned, not built. Everything slots into the
existing registry + review queue when the extension is built.

### 8.8 Mirror refresh scheduler (keep mirrors current without a thundering herd)

Mirrors go stale; new commits — and new attacks — only arrive if we fetch. A
**refresh scheduler** walks every mirrored repo and runs `git remote update`,
but **spreads the work** — a nightly window with per-repo jitter / rate-limiting
— so thousands of repos don't stampede upstreams (GitHub *will* rate-limit) or
spike local IO all at once.

- Refresh is the **trigger** for the on-update pipeline (§8.2): new commits →
  gitleaks `old..new`; new/changed tips → SBOM regen (§8.5); new refs recorded
  in `repo_refs`.
- It is **distinct** from the vuln re-match sweep (§8.5): refresh brings *new
  code* (needs the network + git); re-match re-checks *unchanged code* against a
  drifted DB (needs neither the network nor the repo). Two timers, two purposes.
- **Age-out interacts** with §8.3's sweep age-out: a long-cold repo can drop out
  of *refresh* too, not just the scan sweep — a fresh pull re-activates it (same
  reversible mechanism as §8.3). Knob; default TBD.
- Upstream **rate-limiting** is a real concern at thousands-of-repos scale —
  even anonymous fetches can hit abuse caps — so be a good citizen: backoff +
  jitter. No upstream *auth* (repos are public, §2.1). Minimal in the prototype.

**Sweep set & cadence (resolves §11.1).** The two timers are fully decoupled:
*refresh* runs nightly (jittered per-repo) and triggers on-update scans only for
tips that moved; *vuln re-match* runs on **advisory ingest** (default daily).
Because re-match is a DB join, not a repo scan (§8.5), a fresh advisory feed is
re-matched **immediately** — the old "mark-stale vs. re-sweep on DB update"
dilemma disappears; there is no match-staleness to track. The set either timer
touches is **demand-anchored**: distinct `(repo, ref)` from `access_events` with
last-pull ≥ now − age-out (§8.3) and commit-date ≥ `scan_floor`. Age-out applies
**uniformly, including `main`** (re-activation is automatic — no safety loss); a
per-repo **pin** list forces always-sweep for refs an admin wants monitored
regardless of pull recency.

---

## 9. Data model (revised DDL)

Changes from v1: drop `repos.current_verdict`; add ref/commit scoping to
`verdicts`, `scans`, `findings`, `access_events`; add identity tables; add
`repo_refs` for the timer sweep; key overrides on fingerprint.

```sql
CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ssh_keys (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,          -- SHA256:...
    pubkey      TEXT NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,          -- HTTPS transport
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE repos (
    id           BIGSERIAL PRIMARY KEY,
    upstream_url TEXT NOT NULL UNIQUE,
    mirror_path  TEXT NOT NULL,                -- ${DATA}/mirrors/github.com/owner/repo.git
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced  TIMESTAMPTZ,
    scan_floor   TIMESTAMPTZ                   -- demand-anchored floor (§8.3); refs older than this are unscanned
    -- NOTE: no current_verdict here. Verdicts are (repo, ref)-scoped below.
);

-- Known refs per repo; drives the Trivy timer sweep and incremental gitleaks.
CREATE TABLE repo_refs (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT NOT NULL,                -- refs/heads/main, refs/tags/v1.2
    tip_sha      TEXT NOT NULL,
    last_synced  TIMESTAMPTZ,
    last_scanned TIMESTAMPTZ,
    UNIQUE (repo_id, ref)
);

CREATE TABLE scans (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    scanner      TEXT NOT NULL,                -- 'gitleaks' | 'trivy' | ...
    scope_kind   TEXT NOT NULL CHECK (scope_kind IN ('RANGE','TREE')),
    scope_expr   TEXT,                         -- 'old..new' | ref name
    ref          TEXT,                         -- tree-state scans: which ref
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
    commit_sha   TEXT,                         -- gitleaks: the introducing commit
    fingerprint  TEXT,                         -- stable id for dedup + overrides
    description  TEXT,
    raw          JSONB
);

CREATE TABLE verdicts (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,                         -- NULL = repo-wide
    scan_id      BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    decision     TEXT NOT NULL CHECK (decision IN ('CLEAN','QUARANTINED','OVERRIDDEN')),
    reason       TEXT,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_verdicts_repo_ref_time ON verdicts(repo_id, ref, decided_at DESC);

-- Current verdict per (repo, ref) = latest row.
CREATE VIEW current_verdicts AS
SELECT DISTINCT ON (repo_id, ref)
       repo_id, ref, decision, decided_at
FROM verdicts
ORDER BY repo_id, ref, decided_at DESC;

CREATE TABLE overrides (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,                         -- scope of the override
    fingerprint  TEXT NOT NULL,                -- stable fingerprint (secrets) or vuln source_id
    vex_status   TEXT,                          -- VEX (§8.6): not_affected | fixed | false_positive | accepted
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
    recipients   BIGINT[] NOT NULL,            -- user ids (fallback: source IPs)
    payload_path TEXT NOT NULL,
    sent_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Vulnerability model (§8.6): OSV/PURL/CVSS, deduped globally ──

CREATE TABLE vulnerabilities (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,                -- 'OSV' | 'NVD' | 'GHSA' | 'BDSA' | 'RUSTSEC' | 'MAL'
    source_id    TEXT NOT NULL,                -- 'CVE-2024-3094' | 'GHSA-xxxx' | 'MAL-2024-1'
    aliases      TEXT[] NOT NULL DEFAULT '{}', -- OSV-style cross-links: other ids for the same vuln
    kind         TEXT NOT NULL DEFAULT 'CVE' CHECK (kind IN ('CVE','MALWARE')),
    cvss_vector  TEXT,                         -- self-describing (v3.1/v4.0); NULL for malware
    severity     TEXT CHECK (severity IN ('LOW','MEDIUM','HIGH')),  -- normalized
    summary      TEXT,
    refs         JSONB,
    UNIQUE (source, source_id)
);

-- SBOM per tree-state (§8.5): immutable once written for a tip.
CREATE TABLE components (
    id           BIGSERIAL PRIMARY KEY,
    repo_id      BIGINT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    ref          TEXT,
    tip_sha      TEXT NOT NULL,
    purl         TEXT NOT NULL,                -- pkg:type/name@version
    scan_id      BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    UNIQUE (repo_id, tip_sha, purl)
);

-- Finding = component ⋈ vulnerability, observed by a scan (§8.5).
CREATE TABLE vuln_matches (
    id             BIGSERIAL PRIMARY KEY,
    component_id   BIGINT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    vuln_id        BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    scan_id        BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    scanner        TEXT NOT NULL,              -- 'trivy' | 'blackduck' | ...
    tool_severity  TEXT,                       -- as reported, pre-normalization
    fixed_version  TEXT,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component_id, vuln_id)
);
CREATE INDEX idx_vuln_matches_vuln ON vuln_matches(vuln_id);

-- Triage queue (§6.6): human adjudication for CVE / malicious-code findings.
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
```

---

## 10. Built now vs. deferred

**Built in the prototype:**

- Go front-door: HTTP smart protocol (**Strategy A**) + SSH server + web UI.
- URL-triggered lazy mirror; bare repos on disk; timer refresh.
- Identity: SSH keys + HTTP tokens + self-service key upload.
- Gate + **ERR/stderr block message**; repo-wide and ref-level quarantine via
  `uploadpack.hideRefs`; most-specific-wins resolver.
- Fail-open-once + retroactive per-ref quarantine + notification stub (JSON
  file, as v1).
- Scanners: **gitleaks + Trivy only**, two job types (on-update + on-timer),
  demand-anchored sweep set (§8.8): pulled, in-window `(repo, ref)` above the
  scan floor, age-out uniform + per-repo pin.
- `insteadOf` / `PREMIRRORS` documented as the fetcher-config seam.
- **Vulnerability model split** (§8.5/8.6): SBOM (`components`) stored separately
  from `vuln_matches`; `vulnerabilities` deduped globally, OSV/PURL/CVSS
  normalization with an aliases model (BDSA/GHSA/RUSTSEC/MAL slot in).
- **Review queue / triage webview** (§6.6): CVE + malicious-code findings routed
  to human adjudication with blast-radius; **only secrets auto-quarantine**.
- **Known-malicious via OSV `MAL-` feed** (§8.7) plus the **generic seam** to run
  any detector over the mirror and store its results — **no concrete in-house
  heuristic built now** (that's the deferred extension, §8.7).
- **Mirror refresh scheduler** (§8.8): jittered nightly `git remote update` over
  all mirrors, triggering the on-update pipeline.

**Deferred (unblocked, not built):**

- **Strategy B** (drive `upload-pack`): sideband success-messages +
  reachability-aware want-rejection for the "bad commit merged into clean ref"
  case.
- External / deep scanners (Black Duck, Semgrep, OSV-Scanner) via the
  Descriptor/lane/scope machinery.
- Forgejo (or any rich UI) as an *alternate access surface*.
- OIDC/SSO login; real email/Slack notifications; HA/backup/TLS.
- Manifest pre-resolution (pre-mirroring west/Yocto sub-repos ahead of demand).
- **CVE re-match-without-re-scan** optimization (§8.5): store SBOM + re-join
  against a refreshed vuln DB on a timer. Prototype may just re-run `trivy fs`.
- **VEX import/export** (§8.6): consume upstream projects' VEX, emit our own.
  Adopt the shape now.
- **Policy-based CVE auto-quarantine** (§6.6): KEV/EPSS-driven auto-block as an
  accelerator over the human review queue.
- **The whole in-house supply-chain detection layer** (§8.7) — heuristic diff
  signals (install-script / binary-blob / identity change), external detectors
  (GuardDog, Socket, OpenSSF Package Analysis), and provenance verification
  (SLSA / in-toto / Sigstore / signed-commit). All run on the mirror via the
  generic seam; deferred as the extension on top of the basics.
- **Emit CycloneDX / SARIF** for external consumers (§8.6).

---

## 11. Open questions for the next round

1. ~~**Timer sweep scope & cadence.**~~ **RESOLVED (§8.8).** Two decoupled
   timers: refresh (nightly, jittered) vs. vuln re-match (on advisory ingest,
   daily). Sweep set = demand-anchored pulled `(repo, ref)`; age-out applied
   uniformly incl. `main`, plus a per-repo pin knob. Re-match is a cheap DB
   join, run immediately on ingest — no "mark-stale vs. re-sweep" dilemma, no
   match-staleness. No enumeration of "all live branch tips" — demand only.
2. **First-fetch latency.** ~~Accept-and-note, or add a "mirroring, retry"
   response early?~~ **RESOLVED: accept-and-note.** The first fetch blocks
   while the initial `git clone --mirror` runs (see §2.1). Documented as a
   known limitation; the async retry response is deferred. Revisit only if the
   blocking clone turns out to break a real client's timeout in the demo.
3. ~~**PENDING policy edges.**~~ **RESOLVED (§6.7).** New commits never
   auto-clear a block; the lift test is attribution-dependent. **Secrets**
   (blob-in-history) persist while the introducing commit is *reachable* — a
   delete-without-rewrite does **not** lift them (blob still cloneable); only a
   history rewrite does. **CVE / in-tree malicious** lift on a **clean re-scan
   of the new tip** (tree-state, not reachability) — later removal without
   rewrite *does* clear them — and since human-blocked, this returns the item to
   the triage queue rather than auto-serving.
4. ~~**Override scope.**~~ **RESOLVED (§6.7).** Gate framed as a **blocking
   set**: ref R blocked iff some HIGH finding on R is still applicable *and* not
   overridden. Overriding a fingerprint drops it from the set; R serves when the
   set empties (generalizes v1's "sole finding"). Override scope `(repo, ref?,
   fingerprint)` maps to VEX; override/re-scan triggers a verdict recompute
   (gate stays O(1)). Guardrail: a fingerprint waiver can't lift a *manual*
   repo-wide "toxic" quarantine.
5. **Black Duck (and friends) integration contract.** What does its result
   actually look like, and does the Descriptor/ScanScope shape above survive
   contact with a real async, licensed, API-based scanner?
6. **Triage workflow.** Who is the "responsible owner" per repo (routing of the
   review queue)? Notification cadence for the interval re-match diffs (§8.5) —
   per-finding, digest, threshold-gated?
7. **Refresh scheduler tuning** (§8.8). Nightly window + jitter shape, upstream
   rate-limit/backoff strategy at thousands-of-repos scale, and the refresh
   age-out default for long-cold repos.
8. **Native diff-heuristic set** (§8.7) — *for when the extension is built.*
   Which delta signals are worth the false-positive cost in-house (install-script
   added, binary blob, identity change) vs. delegating entirely to
   Socket/GuardDog/Package Analysis? Basics land first; this is the extension.

---

## 12. What "done" looks like (prototype)

- `docker compose up` brings up the Go proxy + Postgres cleanly.
- A `demo.sh` acceptance test (adapted from v1) that:
  1. clones a known-clean repo through the proxy → served, verdict CLEAN;
  2. pushes/points a **dirty tag** (fake AWS key) at a fixture repo served over
     `file://` → gitleaks flags it → **that ref** is quarantined;
  3. clone of the quarantined ref fails with the `remote:` block message, while
     a clean ref of the same repo still clones;
  4. override by fingerprint → the ref clones again.
- README documents every manual step, the `insteadOf`/`PREMIRRORS` setup, and
  every shortcut (Strategy A limits, fail-open-once, IP fallback, etc.).

Resist the urge to build past this. The deferred list in §10 is deferred on
purpose.
