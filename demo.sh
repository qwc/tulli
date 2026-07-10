#!/usr/bin/env bash
#
# demo.sh — the stage-4 / spec §12 acceptance, driven end to end against the
# docker-compose stack (Postgres + tulli). It builds local fixture repos, brings
# the stack up, and walks the secret-quarantine flow:
#
#   1. clone a known-clean repo            -> served, verdict CLEAN
#   2. a dirty tag (fake AWS key)          -> gitleaks quarantines that ref
#   3. the quarantined ref is withheld     -> clean refs still clone
#   4. override the finding by fingerprint -> the ref clones again
#
# The host only needs `git` and `docker` (with the compose plugin): gitleaks,
# psql, and Postgres all run in containers. The step-4 override is written with
# a direct SQL INSERT — a stand-in for the stage-6 web API (see IMPLEMENTATION §4).
#
# NOTE: this script has not been run in the dev sandbox (no docker/gitleaks
# there); the same arc is guarded automatically by
# internal/e2e/TestE2E_ScanQuarantineAndOverrideLift. Expect to tweak the gitleaks
# fixture if the default ruleset changes.
set -euo pipefail

PROXY="${PROXY:-http://localhost:8080}"
COMPOSE=(docker compose)
FIXTURES="demo/fixtures"

# The compose stack defaults to real https upstreams; the demo runs fully
# offline against the local file:// fixtures and wants a snappy override lift.
export TULLI_UPSTREAM_BASE="file:///fixtures"
export TULLI_RECONCILE_INTERVAL="3s"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "need '$1' on the host"; }

psql() { "${COMPOSE[@]}" exec -T postgres psql -U tulli -d tulli -tAqc "$1"; }

# repo_decision <upstream-suffix> <ref-sql> — current verdict decision, or empty.
repo_decision() {
	psql "SELECT decision FROM verdicts v JOIN repos r ON r.id = v.repo_id
	      WHERE r.upstream_url LIKE '%$1' AND v.ref IS $2
	      ORDER BY decided_at DESC LIMIT 1"
}

advertises() { git ls-remote "$PROXY/repos/$1" 2>/dev/null | grep -q "$2"; }

# decision_is <upstream-suffix> <want> — true when the repo-wide verdict matches.
decision_is() { [ "$(repo_decision "$1" NULL || true)" = "$2" ]; }

# poll <seconds> <cmd...> — run cmd (re-evaluated each try) until it succeeds.
poll() {
	local secs="$1"; shift
	for _ in $(seq 1 "$secs"); do "$@" && return 0; sleep 1; done
	return 1
}

# --- fixtures -------------------------------------------------------------------

git_c() { git -C "$1" -c user.email=demo@tulli -c user.name=demo "${@:2}"; }

# bare_clean <dest> — a fully clean bare repo (one commit on main).
bare_clean() {
	local dest="$1" w="$WORK/src.$RANDOM"
	git init -q -b main "$w"
	echo "hello from tulli demo" > "$w/README.md"
	git_c "$w" add -A; git_c "$w" commit -qm "init"
	git clone -q --bare "$w" "$dest"; rm -rf "$w"
}

# bare_tainted <dest> <aws-key> — clean main plus a tag whose commit leaks a key.
bare_tainted() {
	local dest="$1" key="$2" w="$WORK/src.$RANDOM"
	git init -q -b main "$w"
	echo "clean main" > "$w/README.md"
	git_c "$w" add -A; git_c "$w" commit -qm "init"
	git_c "$w" checkout -q -b leak
	mkdir -p "$w/src"; printf 'AWS_ACCESS_KEY_ID = "%s"\n' "$key" > "$w/src/config.py"
	git_c "$w" add -A; git_c "$w" commit -qm "add deploy config"
	git_c "$w" tag v1-leak            # tag the leaky commit
	git_c "$w" checkout -q main
	git_c "$w" branch -D leak         # drop the branch; the commit lives only under the tag
	git clone -q --bare "$w" "$dest"; rm -rf "$w"
}

need git; need docker

step "Building fixture repos under $FIXTURES"
rm -rf "$FIXTURES"
# A pattern-valid but random AWS key (dodges gitleaks' well-known-example
# allowlist). Built from $RANDOM to avoid a /dev/urandom | head SIGPIPE under
# `set -o pipefail`.
_chars=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
KEY=AKIA
for _ in $(seq 16); do KEY="$KEY${_chars:RANDOM%36:1}"; done
bare_clean   "$FIXTURES/example.com/acme/clean"
bare_tainted "$FIXTURES/example.com/acme/widget" "$KEY"
ok "clean repo + tainted repo (leaky tag v1-leak) built"

step "Bringing up the stack (postgres + tulli)"
# Start from a clean slate: the stack persists mirrors + DB in named volumes,
# and a prior run's already-quarantined widget mirror would break step 2's
# fail-open-once first fetch.
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build
poll 90 advertises "example.com/acme/clean" "" || die "tulli did not come up"
ok "proxy is serving on $PROXY"

step "1) Clone a known-clean repo → served, verdict CLEAN"
git clone -q "$PROXY/repos/example.com/acme/clean" "$WORK/clean"
ok "clean repo cloned through the proxy"
poll 30 decision_is acme/clean CLEAN || die "expected a CLEAN verdict for the clean repo"
ok "repo-wide verdict is CLEAN"

step "2) A dirty tag → gitleaks quarantines that ref (fail-open-once)"
git ls-remote "$PROXY/repos/example.com/acme/widget" >/dev/null
ok "first fetch served without blocking (fail-open-once)"
info "scanning asynchronously…"
poll 60 sh -c "! git ls-remote '$PROXY/repos/example.com/acme/widget' | grep -q refs/tags/v1-leak" \
	|| die "refs/tags/v1-leak was not quarantined"
ok "refs/tags/v1-leak retro-quarantined by gitleaks"
info "verdict: $(psql "SELECT decision||' — '||coalesce(reason,'') FROM verdicts v JOIN repos r ON r.id=v.repo_id WHERE r.upstream_url LIKE '%acme/widget' AND v.ref='refs/tags/v1-leak' ORDER BY decided_at DESC LIMIT 1")"

step "3) The quarantined tag is withheld; clean refs still clone"
advertises "example.com/acme/widget" "refs/heads/main" || die "main should still be advertised"
ok "refs/heads/main still advertised"
if git clone -q -b v1-leak "$PROXY/repos/example.com/acme/widget" "$WORK/leak" 2>/dev/null; then
	die "the quarantined tag must not be cloneable"
fi
ok "git clone -b v1-leak fails (ref hidden — silent under Strategy A; see spec §3.3)"
git clone -q "$PROXY/repos/example.com/acme/widget" "$WORK/widget"
if git -C "$WORK/widget" tag | grep -q v1-leak; then die "the hidden tag leaked into the clone"; fi
ok "a full clone succeeds and omits the hidden tag"

step "4) Override the finding by fingerprint → the ref clones again"
FP="$(psql "SELECT f.fingerprint FROM findings f JOIN repos r ON r.id = f.repo_id
	    WHERE r.upstream_url LIKE '%acme/widget' AND f.ref = 'refs/tags/v1-leak'
	      AND f.fingerprint IS NOT NULL LIMIT 1")"
[ -n "$FP" ] || die "no finding fingerprint found to override"
info "fingerprint: $FP"
psql "INSERT INTO overrides (repo_id, ref, fingerprint, reason, actor)
      SELECT id, 'refs/tags/v1-leak', '$FP', 'demo: reviewed false positive', 'demo'
      FROM repos WHERE upstream_url LIKE '%acme/widget'" >/dev/null
ok "override written (stand-in for the stage-6 web API)"
info "waiting for the reconcile sweep to lift the block…"
poll 30 advertises "example.com/acme/widget" "refs/tags/v1-leak" || die "override did not lift the block"
git clone -q -b v1-leak "$PROXY/repos/example.com/acme/widget" "$WORK/leak2"
ok "refs/tags/v1-leak clones again"

printf '\n\033[1;32mDemo passed.\033[0m Tear down with:  docker compose down -v\n'
