#!/usr/bin/env bash
# Reproduce the tulli stage-0 spike: prove the git-http-backend CGI handoff
# (IMPLEMENTATION.md §5 stage 0). Self-contained; uses a temp workspace.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
srv=""
cleanup() { [ -n "$srv" ] && kill "$srv" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

mkdir -p "$work/repos"

# Fixture: a bare repo with one commit (stands in for a real bare mirror).
git init -q -b main "$work/src"
printf 'hello from tulli stage-0 spike\n' > "$work/src/README.md"
git -C "$work/src" -c user.email=spike@tulli.local -c user.name=spike add -A
git -C "$work/src" -c user.email=spike@tulli.local -c user.name=spike commit -q -m "initial spike commit"
git clone -q --bare "$work/src" "$work/repos/spike.git"

# Build + run the spike server (build from the module dir, not the caller's cwd).
( cd "$here" && go build -o "$work/tulli-spike" . )
"$work/tulli-spike" -addr :8099 -root "$work/repos" & srv=$!

# Wait for readiness (curl retry, no shell sleep), then clone THROUGH the proxy.
curl --retry-connrefused --retry 30 --retry-delay 1 -sf \
  "http://localhost:8099/spike.git/info/refs?service=git-upload-pack" >/dev/null
git clone -q http://localhost:8099/spike.git "$work/cloned"

# Verify: cloned tip must equal origin tip.
cloned="$(git -C "$work/cloned" rev-parse HEAD)"
origin="$(git --git-dir="$work/repos/spike.git" rev-parse refs/heads/main)"
if [ "$cloned" = "$origin" ]; then
  echo "STAGE-0 PASS: clone through proxy OK; tip $cloned matches origin"
else
  echo "STAGE-0 FAIL: cloned=$cloned origin=$origin"; exit 1
fi
