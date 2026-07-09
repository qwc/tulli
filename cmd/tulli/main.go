// Command tulli is the FOSS repo proxy (see prototype-spec-v2.md,
// IMPLEMENTATION.md). A single read-only binary that lazily mirrors a public
// upstream on first fetch, gates it against the verdict store (repo-wide block
// via ERR pkt-line, ref-level via uploadpack.hideRefs — spec §6), serves it via
// git-http-backend, scans it asynchronously (gitleaks, fail-open-once, spec §7),
// and reconciles the on-disk quarantine to the DB. Identity, Trivy/CVE, and the
// web/triage UI (the operator-facing writer) land in later stages behind the
// same seams.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/httpsrv"
	"codeberg.org/qwc/tulli/internal/mirror"
	"codeberg.org/qwc/tulli/internal/scan"
	"codeberg.org/qwc/tulli/internal/sshsrv"
	"codeberg.org/qwc/tulli/internal/store"
	"codeberg.org/qwc/tulli/internal/store/pg"
)

// backend is the full persistence surface tulli needs: the audit hallway
// (core.Store), the scan writer (scan.Store), and the reconcile reader
// (mirror.Store). Both internal/store.Mem and internal/store/pg satisfy it.
type backend interface {
	core.Store
	scan.Store
	mirror.Store
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDuration reads a Go duration (e.g. "3s", "30s") from key, falling back to def.
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func main() {
	addr := flag.String("addr", envOr("TULLI_ADDR", ":8080"), "HTTP listen address")
	sshAddr := flag.String("ssh-addr", envOr("TULLI_SSH_ADDR", ""), "SSH listen address (e.g. :2222); empty disables the SSH door")
	data := flag.String("data", envOr("TULLI_DATA", "./data"), "data dir (mirrors live in <data>/mirrors)")
	upstreamBase := flag.String("upstream-base", envOr("TULLI_UPSTREAM_BASE", "https://"),
		"upstream base: a bare scheme like https:// (default) or a URL prefix for file:// fixtures")
	reconcile := flag.Duration("reconcile-interval", envDuration("TULLI_RECONCILE_INTERVAL", 30*time.Second),
		"how often the reconcile safety sweep runs (catches out-of-process verdict/override writes)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	httpBackend, err := git.NewBackend()
	if err != nil {
		log.Error("git http-backend unavailable", "err", err)
		os.Exit(1)
	}

	mirrorRoot := filepath.Join(*data, "mirrors")
	if err := os.MkdirAll(mirrorRoot, 0o755); err != nil {
		log.Error("cannot create mirror root", "path", mirrorRoot, "err", err)
		os.Exit(1)
	}

	m := git.NewMirror(mirrorRoot, *upstreamBase, log)

	// Store: Postgres when TULLI_DATABASE_URL is set, else in-memory
	// (non-persistent). Both satisfy the full backend surface.
	var st backend
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

	ctx := context.Background()

	// Reconciler (mirror-owning process): applies DB verdicts to on-disk hideRefs;
	// its periodic sweep also recomputes verdicts written out of process (the
	// future web API). Scan worker: fail-open-once gitleaks off the request path.
	reconciler := mirror.NewReconciler(st, log)
	worker := scan.NewWorker(scan.NewGitleaks(), st, git.RefsContaining, reconciler, log)
	go worker.Run(ctx)
	go reconciler.Run(ctx, *reconcile)

	gate := core.New(m, st, worker, log)

	// SSH door (second transport onto the same hallway). Optional: only when an
	// address is configured. Anonymous in this stage (see internal/sshsrv).
	if *sshAddr != "" {
		hostKey, err := sshsrv.LoadOrCreateHostKey(filepath.Join(*data, "ssh_host_ed25519_key"))
		if err != nil {
			log.Error("ssh host key unavailable", "err", err)
			os.Exit(1)
		}
		ssrv := sshsrv.New(gate, hostKey, log)
		go func() {
			log.Info("tulli ssh listening", "addr", *sshAddr)
			if err := ssrv.ListenAndServe(ctx, *sshAddr); err != nil {
				log.Error("ssh server exited", "err", err)
				os.Exit(1)
			}
		}()
	}

	srv := httpsrv.New(gate, httpBackend, log)
	log.Info("tulli listening", "addr", *addr, "mirrors", mirrorRoot, "upstreamBase", *upstreamBase, "store", storeKind)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}
