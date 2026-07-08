// Stage-0 spike for `tulli` (IMPLEMENTATION.md §5, stage 0).
//
// Goal: prove Strategy A — that we can hand a git smart-HTTP request off to the
// real `git http-backend` from a Go net/http server via net/http/cgi, and that
// a real `git clone` against it succeeds. No DB, no gate, no mirror, no
// identity. Throwaway/reference only.
//
// If this works, the CGI handoff that the whole prototype rests on is validated.
package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/cgi"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	addr := flag.String("addr", ":8099", "listen address")
	root := flag.String("root", "/tmp/tulli-spike/repos", "GIT_PROJECT_ROOT (dir of bare repos)")
	flag.Parse()

	// Locate the real git-http-backend via git itself (portable, no hardcoded path).
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		log.Fatalf("git --exec-path failed: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")

	// The CGI handler drives git-http-backend. net/http/cgi fills in the standard
	// CGI env (PATH_INFO, QUERY_STRING, REQUEST_METHOD, CONTENT_TYPE, ...) from the
	// HTTP request; we add the git-specific bits.
	//
	// Root="" mounts at "/", so PATH_INFO == the request path, e.g.
	//   /spike.git/info/refs   ->  GIT_PROJECT_ROOT/spike.git + /info/refs
	// The real tulli will mount under /repos/{host}/{owner}/{repo} and strip that
	// prefix; here we keep it flat to isolate the handoff mechanism.
	h := &cgi.Handler{
		Path: backend,
		Root: "",
		Dir:  *root,
		Env: []string{
			"GIT_PROJECT_ROOT=" + *root,
			"GIT_HTTP_EXPORT_ALL=1", // serve repos without a git-daemon-export-ok marker
		},
	}

	// Wrap so we can see exactly what git asks for — proof the handoff fires.
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("-> %s %s?%s (%s)", r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type"))
		h.ServeHTTP(w, r)
	})

	log.Printf("spike serving %s from GIT_PROJECT_ROOT=%s via %s", *addr, *root, backend)
	log.Fatal(http.ListenAndServe(*addr, logged))
}
