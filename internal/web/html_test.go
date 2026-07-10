package web_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/qwc/tulli/internal/store"
)

// noRedirect is an http.Client that captures a redirect response instead of
// following it, so tests can assert on the 303 and the Set-Cookie.
func noRedirect(jar http.CookieJar) *http.Client {
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// browserLogin runs the token→session-cookie login and returns a cookie-jar
// client, asserting the login succeeded.
func browserLogin(t *testing.T, ts *httptest.Server, token string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"token": {token}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
	return c
}

func getBody(t *testing.T, c *http.Client, urlStr string) (int, string) {
	t.Helper()
	resp, err := c.Get(urlStr)
	if err != nil {
		t.Fatalf("GET %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestUI_UnauthenticatedRedirectsToLogin(t *testing.T) {
	ts, _ := newAPI(t)
	c := noRedirect(nil)
	code, _ := getBody(t, c, ts.URL+"/")
	if code != http.StatusSeeOther {
		t.Fatalf("GET / unauthenticated = %d, want 303 to /login", code)
	}
}

func TestUI_LoginBadTokenRejected(t *testing.T) {
	ts, _ := newAPI(t)
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"token": {"nope"}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad-token login = %d, want 401", resp.StatusCode)
	}
	// No session established: root still redirects to login.
	if code, _ := getBody(t, c, ts.URL+"/"); code != http.StatusSeeOther {
		t.Fatalf("after failed login GET / = %d, want 303", code)
	}
}

func TestUI_ReviewerBlockViaForm(t *testing.T) {
	ts, mem := newAPI(t)
	ctx := context.Background()
	id, _ := mem.UpsertRepo(ctx, "https://h/o/r", "/m/r.git")
	_, tok := mkUser(t, ts, "rev", "reviewer", "human")

	c := browserLogin(t, ts, tok)

	// Repo list shows the repo, detail page shows the edit forms.
	if code, body := getBody(t, c, ts.URL+"/"); code != 200 || !strings.Contains(body, "/repos/1") {
		t.Fatalf("repo list = %d, missing repo link\n%s", code, body)
	}
	if code, body := getBody(t, c, ts.URL+"/repos/1"); code != 200 || !strings.Contains(body, "Block a ref") {
		t.Fatalf("repo detail = %d, missing block form (CanEdit)\n%s", code, body)
	}

	// Submit the block form.
	resp, err := c.PostForm(ts.URL+"/repos/1/block", url.Values{
		"ref":    {"refs/heads/evil"},
		"reason": {"planted secret"},
	})
	if err != nil {
		t.Fatalf("block post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("block form = %d, want 303", resp.StatusCode)
	}

	// The intent landed in the store.
	active, reason, err := mem.ActiveManualBlock(ctx, id, "refs/heads/evil")
	if err != nil || !active || reason != "planted secret" {
		t.Fatalf("ActiveManualBlock = (%v, %q, %v), want (true, planted secret, nil)", active, reason, err)
	}
}

func TestUI_ViewerCannotWrite(t *testing.T) {
	ts, mem := newAPI(t)
	mem.UpsertRepo(context.Background(), "https://h/o/r", "/m/r.git")
	_, tok := mkUser(t, ts, "viewer1", "viewer", "human")

	c := browserLogin(t, ts, tok)

	// Detail page renders but WITHOUT the reviewer forms.
	if code, body := getBody(t, c, ts.URL+"/repos/1"); code != 200 || strings.Contains(body, "Block a ref") {
		t.Fatalf("viewer detail = %d, should not show block form\n%s", code, body)
	}
	// And a write is forbidden.
	resp, err := c.PostForm(ts.URL+"/repos/1/block", url.Values{"ref": {"x"}, "reason": {"y"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer block = %d, want 403", resp.StatusCode)
	}
}

func TestUI_LogoutClearsSession(t *testing.T) {
	ts, _ := newAPI(t)
	_, tok := mkUser(t, ts, "rev", "reviewer", "human")
	c := browserLogin(t, ts, tok)

	if code, _ := getBody(t, c, ts.URL+"/"); code != 200 {
		t.Fatalf("pre-logout GET / = %d, want 200", code)
	}
	resp, err := c.PostForm(ts.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303", resp.StatusCode)
	}
	if code, _ := getBody(t, c, ts.URL+"/"); code != http.StatusSeeOther {
		t.Fatalf("post-logout GET / = %d, want 303 (session cleared)", code)
	}
}

// seedTriageItem creates a repo with one PENDING CVE triage row and returns
// (repoID, triageID) — mirrors what the DeepWorker produces.
func seedTriageItem(t *testing.T, mem *store.Mem) (int64, int64) {
	t.Helper()
	ctx := context.Background()
	repoID, _ := mem.UpsertRepo(ctx, "https://h/o/app", "/m/app.git")
	scanID, _ := mem.InsertTreeScan(ctx, repoID, "trivy", "refs/heads/main", "tip1")
	vulnID, _ := mem.UpsertVulnerability(ctx, "nvd", "CVE-2023-1111", nil, "CVE", "HIGH", "", "SSRF")
	compID, _ := mem.UpsertComponent(ctx, repoID, "refs/heads/main", "tip1", "pkg:pypi/requests@2.19.0", scanID)
	matchID, _ := mem.UpsertVulnMatch(ctx, compID, vulnID, scanID, "trivy", "CRITICAL", "2.20.0")
	_ = mem.OpenTriage(ctx, repoID, "refs/heads/main", matchID)
	items, _ := mem.ListPendingTriage(ctx)
	if len(items) != 1 {
		t.Fatalf("seed: got %d pending items, want 1", len(items))
	}
	return repoID, items[0].TriageID
}

func TestUI_TriageQuarantineWritesBlock(t *testing.T) {
	ts, mem := newAPI(t)
	ctx := context.Background()
	repoID, triageID := seedTriageItem(t, mem)
	_, tok := mkUser(t, ts, "rev", "reviewer", "human")
	c := browserLogin(t, ts, tok)

	// Queue page lists the pending item.
	if code, body := getBody(t, c, ts.URL+"/triage"); code != 200 || !strings.Contains(body, "CVE-2023-1111") {
		t.Fatalf("triage queue = %d, missing item\n%s", code, body)
	}

	// Quarantine decision → 303, records a manual block on the ref.
	resp, err := c.PostForm(ts.URL+"/triage/"+itoa(triageID),
		url.Values{"decision": {"quarantine"}, "note": {"exploitable"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("quarantine = %d, want 303", resp.StatusCode)
	}
	active, reason, _ := mem.ActiveManualBlock(ctx, repoID, "refs/heads/main")
	if !active || !strings.Contains(reason, "CVE-2023-1111") {
		t.Fatalf("manual block = (%v, %q), want active with the CVE id", active, reason)
	}
	// Item leaves the PENDING queue.
	if items, _ := mem.ListPendingTriage(ctx); len(items) != 0 {
		t.Fatalf("queue still has %d items after decision", len(items))
	}
}

func TestUI_TriageViewerForbidden(t *testing.T) {
	ts, _ := newAPI(t)
	_, tok := mkUser(t, ts, "v", "viewer", "human")
	c := browserLogin(t, ts, tok)
	if code, _ := getBody(t, c, ts.URL+"/triage"); code != http.StatusForbidden {
		t.Fatalf("viewer /triage = %d, want 403", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestUI_AdminOnlyUsersPage(t *testing.T) {
	ts, _ := newAPI(t)

	// Bootstrap admin can view the users page.
	admin := browserLogin(t, ts, adminTok)
	if code, body := getBody(t, admin, ts.URL+"/users"); code != 200 || !strings.Contains(body, "Create a user") {
		t.Fatalf("admin /users = %d, missing create form\n%s", code, body)
	}

	// A reviewer is forbidden.
	_, tok := mkUser(t, ts, "rev", "reviewer", "human")
	rev := browserLogin(t, ts, tok)
	if code, _ := getBody(t, rev, ts.URL+"/users"); code != http.StatusForbidden {
		t.Fatalf("reviewer /users = %d, want 403", code)
	}
}
