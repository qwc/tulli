package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/store"
	"codeberg.org/qwc/tulli/internal/verdict"
	"codeberg.org/qwc/tulli/internal/web"
)

const adminTok = "bootstrap-admin-secret"

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newAPI(t *testing.T) (*httptest.Server, *store.Mem) {
	t.Helper()
	mem := store.NewMem()
	srv := web.New(mem, auth.NewDBProvider(mem), adminTok, []byte("test-secret"), false, discardLogger())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, mem
}

// req performs an API call with an optional bearer token and returns the status
// and body.
func req(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	r, err := http.NewRequest(method, ts.URL+path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// mkUser exercises the admin identity endpoints to create a user and mint a token
// for it — the bootstrap chain — and returns the user id and its raw token.
func mkUser(t *testing.T, ts *httptest.Server, name, role, kind string) (int64, string) {
	t.Helper()
	code, body := req(t, ts, "POST", "/api/users", adminTok, map[string]any{"name": name, "role": role, "kind": kind})
	if code != http.StatusCreated {
		t.Fatalf("create user %s: %d %s", name, code, body)
	}
	var u struct {
		ID int64 `json:"id"`
	}
	mustJSON(t, body, &u)

	code, body = req(t, ts, "POST", fmt.Sprintf("/api/users/%d/tokens", u.ID), adminTok, nil)
	if code != http.StatusCreated {
		t.Fatalf("create token: %d %s", code, body)
	}
	var tk struct {
		Token string `json:"token"`
	}
	mustJSON(t, body, &tk)
	if tk.Token == "" {
		t.Fatal("empty token returned")
	}
	return u.ID, tk.Token
}

func mustJSON(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("bad JSON %q: %v", raw, err)
	}
}

func TestAPI_RequiresAuth(t *testing.T) {
	ts, _ := newAPI(t)
	if code, _ := req(t, ts, "GET", "/api/repos", "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", code)
	}
	if code, _ := req(t, ts, "GET", "/api/repos", "not-a-real-token", nil); code != http.StatusUnauthorized {
		t.Errorf("bogus token: status = %d, want 401", code)
	}
}

func TestAPI_RBAC_ViewerCannotWrite(t *testing.T) {
	ts, mem := newAPI(t)
	id, _ := mem.UpsertRepo(context.Background(), "https://h/o/r", "/m/r.git")
	_, viewerTok := mkUser(t, ts, "vic", "viewer", "human")

	// viewer reads fine…
	if code, _ := req(t, ts, "GET", "/api/repos", viewerTok, nil); code != http.StatusOK {
		t.Errorf("viewer GET repos = %d, want 200", code)
	}
	// …but cannot block.
	code, _ := req(t, ts, "POST", fmt.Sprintf("/api/repos/%d/block", id), viewerTok,
		map[string]any{"ref": "refs/heads/evil", "reason": "nope"})
	if code != http.StatusForbidden {
		t.Errorf("viewer block = %d, want 403", code)
	}
}

func TestAPI_ReviewerBlockWritesIntent(t *testing.T) {
	ts, mem := newAPI(t)
	ctx := context.Background()
	id, _ := mem.UpsertRepo(ctx, "https://h/o/r", "/m/r.git")
	_, revTok := mkUser(t, ts, "rae", "reviewer", "human")

	code, body := req(t, ts, "POST", fmt.Sprintf("/api/repos/%d/block", id), revTok,
		map[string]any{"ref": "refs/heads/evil", "reason": "suspected malware"})
	if code != http.StatusAccepted {
		t.Fatalf("reviewer block = %d %s, want 202", code, body)
	}
	// The manual-block intent landed (attributed to the reviewer); the reconciler
	// turns it into an enforced verdict out of band.
	active, reason, err := mem.ActiveManualBlock(ctx, id, "refs/heads/evil")
	if err != nil || !active || reason != "suspected malware" {
		t.Fatalf("ActiveManualBlock = %v/%q/%v, want active with the reason", active, reason, err)
	}

	// A block with no reason is rejected.
	if code, _ := req(t, ts, "POST", fmt.Sprintf("/api/repos/%d/block", id), revTok,
		map[string]any{"ref": "refs/heads/x"}); code != http.StatusBadRequest {
		t.Errorf("reasonless block = %d, want 400", code)
	}
}

func TestAPI_OverrideWritesIntent(t *testing.T) {
	ts, mem := newAPI(t)
	ctx := context.Background()
	id, _ := mem.UpsertRepo(ctx, "https://h/o/r", "/m/r.git")
	_, revTok := mkUser(t, ts, "rae", "reviewer", "human")

	code, body := req(t, ts, "POST", fmt.Sprintf("/api/repos/%d/overrides", id), revTok,
		map[string]any{"ref": "refs/heads/evil", "fingerprint": "fp-1", "reason": "false positive"})
	if code != http.StatusAccepted {
		t.Fatalf("override = %d %s, want 202", code, body)
	}
	fps, err := mem.OverriddenFingerprints(ctx, id, "refs/heads/evil")
	if err != nil || len(fps) != 1 || fps[0] != "fp-1" {
		t.Fatalf("OverriddenFingerprints = %v, %v, want [fp-1]", fps, err)
	}
}

// TestAPI_OverrideMarksFindingWaived is the #21 regression: after a finding is
// overridden, the repo detail must report it as waived and carry the reason +
// actor (previously the override was invisible in the findings list).
func TestAPI_OverrideMarksFindingWaived(t *testing.T) {
	ts, mem := newAPI(t)
	ctx := context.Background()
	id, _ := mem.UpsertRepo(ctx, "https://h/o/r", "/m/r.git")
	scanID, err := mem.InsertScan(ctx, id, "gitleaks", "refs/heads/evil", "state")
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.InsertFinding(ctx, scanID, id, "refs/heads/evil", verdict.Finding{
		Scanner: "gitleaks", Severity: "HIGH", RuleID: "aws-access-token",
		FilePath: "config.py", Commit: "deadbeef", Fingerprint: "fp-1",
	}); err != nil {
		t.Fatal(err)
	}
	_, revTok := mkUser(t, ts, "rae", "reviewer", "human")

	// Before the waiver, the finding shows as not waived.
	detail := getDetail(t, ts, id, revTok)
	if len(detail.Findings) != 1 || detail.Findings[0].Waived {
		t.Fatalf("pre-waiver findings = %+v, want one non-waived", detail.Findings)
	}

	code, body := req(t, ts, "POST", fmt.Sprintf("/api/repos/%d/overrides", id), revTok,
		map[string]any{"ref": "refs/heads/evil", "fingerprint": "fp-1", "reason": "revoked key"})
	if code != http.StatusAccepted {
		t.Fatalf("override = %d %s, want 202", code, body)
	}

	detail = getDetail(t, ts, id, revTok)
	if len(detail.Findings) != 1 {
		t.Fatalf("post-waiver findings = %+v, want one", detail.Findings)
	}
	f := detail.Findings[0]
	if !f.Waived || f.WaiverReason != "revoked key" || f.WaivedBy != "rae" {
		t.Fatalf("finding = %+v, want waived with reason 'revoked key' by rae", f)
	}
}

type findingJSON struct {
	Waived       bool   `json:"waived"`
	WaiverReason string `json:"waiver_reason"`
	WaivedBy     string `json:"waived_by"`
}

func getDetail(t *testing.T, ts *httptest.Server, id int64, token string) struct {
	Findings []findingJSON `json:"findings"`
} {
	t.Helper()
	code, body := req(t, ts, "GET", fmt.Sprintf("/api/repos/%d", id), token, nil)
	if code != http.StatusOK {
		t.Fatalf("get repo = %d %s", code, body)
	}
	var out struct {
		Findings []findingJSON `json:"findings"`
	}
	mustJSON(t, body, &out)
	return out
}

func TestAPI_AdminCreateUserValidation(t *testing.T) {
	ts, _ := newAPI(t)
	// A non-admin cannot create users.
	_, revTok := mkUser(t, ts, "rae", "reviewer", "human")
	if code, _ := req(t, ts, "POST", "/api/users", revTok,
		map[string]any{"name": "x", "role": "viewer", "kind": "human"}); code != http.StatusForbidden {
		t.Errorf("reviewer create user = %d, want 403", code)
	}
	// An invalid role is a 400.
	if code, _ := req(t, ts, "POST", "/api/users", adminTok,
		map[string]any{"name": "x", "role": "superuser", "kind": "human"}); code != http.StatusBadRequest {
		t.Errorf("bad role = %d, want 400", code)
	}
}

func TestAPI_ListReposShowsVerdict(t *testing.T) {
	ts, mem := newAPI(t)
	ctx := context.Background()
	id, _ := mem.UpsertRepo(ctx, "https://h/o/r", "/m/r.git")
	mem.SetVerdict(id, "", "QUARANTINED", "toxic")

	code, body := req(t, ts, "GET", "/api/repos", adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list repos = %d %s", code, body)
	}
	var repos []struct {
		ID      int64  `json:"id"`
		Blocked bool   `json:"blocked"`
		Reason  string `json:"reason"`
	}
	mustJSON(t, body, &repos)
	if len(repos) != 1 || repos[0].ID != id || !repos[0].Blocked || repos[0].Reason != "toxic" {
		t.Fatalf("repos = %+v, want one blocked repo with reason toxic", repos)
	}
}
