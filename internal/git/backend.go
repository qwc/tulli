package git

import (
	"fmt"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Backend hands a smart-HTTP request off to the real `git http-backend` via CGI
// (Strategy A, spec §3.1 — validated in spike/stage0). Once handed off, git owns
// the byte stream, so a block must be written *before* Serve is called (the
// gate does this at info/refs in a later stage; §3.3).
type Backend struct {
	path string // absolute path to git-http-backend
}

// NewBackend locates git-http-backend via `git --exec-path` (portable).
func NewBackend() (*Backend, error) {
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		return nil, fmt.Errorf("git --exec-path: %w", err)
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("git-http-backend not found at %s: %w", p, err)
	}
	return &Backend{path: p}, nil
}

// Serve streams the response for the bare repo at repoPath and the given verb.
//
// git-http-backend resolves the repo from GIT_PROJECT_ROOT + PATH_INFO. We point
// GIT_PROJECT_ROOT at the repo's parent and set PATH_INFO to "/<repo>.git/<verb>",
// which keeps this driven entirely by the Admission — the transport needs
// nothing but repoPath.
func (b *Backend) Serve(w http.ResponseWriter, r *http.Request, repoPath, verb string) {
	projectRoot := filepath.Dir(repoPath)
	repoName := filepath.Base(repoPath) // e.g. repo.git

	// Rewrite the path the CGI sees; cgi.Handler derives PATH_INFO from URL.Path.
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/" + repoName + "/" + verb
	r2.URL.RawPath = ""

	h := &cgi.Handler{
		Path: b.path,
		Root: "", // mounted at "/", so PATH_INFO == the rewritten URL.Path
		Dir:  projectRoot,
		Env: []string{
			"GIT_PROJECT_ROOT=" + projectRoot,
			"GIT_HTTP_EXPORT_ALL=1", // serve without a git-daemon-export-ok marker
		},
	}
	h.ServeHTTP(w, r2)
}
