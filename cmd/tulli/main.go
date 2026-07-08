// Command tulli is the FOSS repo proxy (see prototype-spec-v2.md,
// IMPLEMENTATION.md). Stage 1: a single read-only binary that lazily mirrors a
// public upstream on first fetch and serves it via git-http-backend. No gate,
// scan, identity, or store yet — those land in later stages behind the same
// seams.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/httpsrv"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", envOr("TULLI_ADDR", ":8080"), "listen address")
	data := flag.String("data", envOr("TULLI_DATA", "./data"), "data dir (mirrors live in <data>/mirrors)")
	upstreamBase := flag.String("upstream-base", envOr("TULLI_UPSTREAM_BASE", "https://"),
		"upstream base: a bare scheme like https:// (default) or a URL prefix for file:// fixtures")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	backend, err := git.NewBackend()
	if err != nil {
		log.Error("git http-backend unavailable", "err", err)
		os.Exit(1)
	}

	mirrorRoot := filepath.Join(*data, "mirrors")
	if err := os.MkdirAll(mirrorRoot, 0o755); err != nil {
		log.Error("cannot create mirror root", "path", mirrorRoot, "err", err)
		os.Exit(1)
	}

	mirror := git.NewMirror(mirrorRoot, *upstreamBase, log)
	gate := core.New(mirror, log)
	srv := httpsrv.New(gate, backend, log)

	log.Info("tulli stage-1 listening", "addr", *addr, "mirrors", mirrorRoot, "upstreamBase", *upstreamBase)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}
