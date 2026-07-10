package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/web"
)

// TestE2E_WebBlockQuarantines is the stage-6b capstone: a human blocks a ref
// through the web API (bearer-token authenticated), the reconciler sweep turns
// that intent into an enforced verdict, and the git side hides the ref — the full
// human-intent → enforcement loop, driven entirely through the API instead of SQL.
func TestE2E_WebBlockQuarantines(t *testing.T) {
	const adminTok = "admin-secret"
	up := t.TempDir()
	repo := filepath.Join(up, "example.com/acme/widget")
	makeUpstream(t, repo, "clean main\n")
	makeUpstreamBranch(t, repo, "evil", "nothing a scanner catches\n")

	s := newStack(t, "file://"+up, noopScanner{})
	gitURL := s.ts.URL + "/repos/example.com/acme/widget"

	// Register the repo (both refs present) and get its id.
	if refs := lsRemote(t, gitURL); !refs["refs/heads/evil"] || !refs["refs/heads/main"] {
		t.Fatalf("expected both refs advertised, got %v", refs)
	}
	ref := git.RepoRef{Host: "example.com", Path: "acme/widget"}
	id, ok := s.st.RepoID(ref.UpstreamURL("file://" + up))
	if !ok {
		t.Fatal("repo not registered")
	}

	// Web API over the same store (its own httptest server).
	api := httptest.NewServer(web.New(s.st, auth.NewDBProvider(s.st), adminTok, []byte("test-secret"), false, discardLogger()).Handler())
	t.Cleanup(api.Close)

	// A reviewer blocks the ref through the API (bootstrap admin authenticates).
	body, _ := json.Marshal(map[string]any{"ref": "refs/heads/evil", "reason": "malware, reported via web"})
	r, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/repos/%d/block", api.URL, id), bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+adminTok)
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("block via API = %d, want 202", resp.StatusCode)
	}

	// The reconciler applies the DB desired-state to disk; the ref is now hidden.
	if err := s.reconciler.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	refs := lsRemote(t, gitURL)
	if refs["refs/heads/evil"] {
		t.Errorf("ref blocked via the API must be hidden; got %v", refs)
	}
	if !refs["refs/heads/main"] {
		t.Errorf("clean ref main must stay advertised; got %v", refs)
	}
}
