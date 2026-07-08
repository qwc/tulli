// Command tulli is the FOSS repo proxy (see prototype-spec-v2.md,
// IMPLEMENTATION.md). Stage 1: a single read-only binary that lazily mirrors a
// public upstream on first fetch and serves it via git-http-backend. No gate,
// scan, identity, or store yet — those land in later stages behind the same
// seams.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/httpsrv"
	"codeberg.org/qwc/tulli/internal/store"
	"codeberg.org/qwc/tulli/internal/store/pg"
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

	// Audit store: Postgres when TULLI_DATABASE_URL is set, else in-memory
	// (non-persistent). Both satisfy the core.Store seam.
	var st core.Store
	storeKind := "mem (non-persistent)"
	if dsn := envOr("TULLI_DATABASE_URL", ""); dsn != "" {
		pgs, err := pg.Open(context.Background(), dsn)
		if err != nil {
			log.Error("postgres store unavailable", "err", err)
			os.Exit(1)
		}
		defer pgs.Close()
		st = pgs
		storeKind = "postgres"
	} else {
		st = store.NewMem()
	}

	gate := core.New(mirror, st, log)
	srv := httpsrv.New(gate, backend, log)

	log.Info("tulli listening", "addr", *addr, "mirrors", mirrorRoot, "upstreamBase", *upstreamBase, "store", storeKind)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}
