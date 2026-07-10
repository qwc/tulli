// Package web is tulli's human-facing surface (stage 6b): a JSON API — driven by
// the browser UI and by tullictl — for reading state (repos, verdicts, findings)
// and writing human intents (manual blocks, overrides) and identities (users,
// tokens, keys). It is the single writer of human decisions (IMPLEMENTATION §4):
// it only touches the database (desired state); the reconciler in the git-serving
// process applies those decisions to disk. So it runs on its own port, off the
// public git surface, and here as a goroutine that could later split into its own
// executable against the same DB without a rewrite.
//
// Authentication is by bearer token (auth.Authenticator) plus a bootstrap admin
// token from config, which mints the first real users. Authorization is the
// minimal role model from stage 6a — viewer reads, reviewer writes intents, admin
// manages identities. LDAP/OIDC and cookie sessions join this via the same auth
// seam later (stage 6b-ui / 6e); passwords are intentionally skipped.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/verdict"
)

// sessionTTL is how long a browser session cookie stays valid. Role/kind are
// re-resolved every request regardless, so this only bounds re-login frequency.
const sessionTTL = 12 * time.Hour

// Store is the persistence surface the web API needs: reads for the views and
// intent/identity writes. Every method already exists on internal/store.Mem and
// internal/store/pg — the web composes existing seams, adding none.
type Store interface {
	ListRepos(ctx context.Context) ([]core.RepoInfo, error)
	ResolveVerdict(ctx context.Context, repoID int64) (core.Verdict, error)
	AffectedRefs(ctx context.Context, repoID int64) ([]string, error)
	FindingsForRef(ctx context.Context, repoID int64, ref string) ([]verdict.Finding, error)
	InsertManualBlock(ctx context.Context, repoID int64, ref string, active bool, reason, actor string) error
	InsertOverride(ctx context.Context, repoID int64, ref, fingerprint, reason, actor string) error
	InsertUser(ctx context.Context, name string, role auth.Role, kind auth.Kind) (int64, error)
	InsertToken(ctx context.Context, userID int64, tokenHash string) error
	InsertSSHKey(ctx context.Context, userID int64, fingerprint, pubkey string) error
	// UserByID re-resolves the session principal each request (revocation).
	UserByID(ctx context.Context, userID int64) (auth.Identity, bool, error)
	// ListUsers backs the admin users view.
	ListUsers(ctx context.Context) ([]auth.Identity, error)
	// VulnMatchesForRepo backs the (read-only) CVE section of the repo page.
	VulnMatchesForRepo(ctx context.Context, repoID int64) ([]core.VulnMatch, error)
}

type Server struct {
	store         Store
	authr         auth.Authenticator
	adminToken    string // bootstrap admin bearer token (empty = no bootstrap admin)
	sessions      *sessions
	secureCookies bool
	tmpl          map[string]*template.Template
	log           *slog.Logger
}

// New builds the web server. sessionSecret signs browser session cookies (a
// random per-process secret means sessions do not survive restart / are not
// shared across replicas — set it in prod). secureCookies marks the session
// cookie Secure (set true behind TLS; false for the plain-HTTP prototype).
func New(store Store, authr auth.Authenticator, adminToken string, sessionSecret []byte, secureCookies bool, log *slog.Logger) *Server {
	return &Server{
		store:         store,
		authr:         authr,
		adminToken:    adminToken,
		sessions:      newSessions(sessionSecret, sessionTTL),
		secureCookies: secureCookies,
		tmpl:          parseTemplates(),
		log:           log,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})

	// JSON API (tullictl + programmatic clients) — bearer-token auth.
	mux.HandleFunc("GET /api/repos", s.guard(auth.RoleViewer, s.listRepos))
	mux.HandleFunc("GET /api/repos/{id}", s.guard(auth.RoleViewer, s.getRepo))
	mux.HandleFunc("POST /api/repos/{id}/block", s.guard(auth.RoleReviewer, s.blockRef))
	mux.HandleFunc("POST /api/repos/{id}/unblock", s.guard(auth.RoleReviewer, s.unblockRef))
	mux.HandleFunc("POST /api/repos/{id}/overrides", s.guard(auth.RoleReviewer, s.addOverride))
	mux.HandleFunc("POST /api/users", s.guard(auth.RoleAdmin, s.createUser))
	mux.HandleFunc("POST /api/users/{id}/tokens", s.guard(auth.RoleAdmin, s.createToken))
	mux.HandleFunc("POST /api/users/{id}/keys", s.guard(auth.RoleAdmin, s.addKey))

	// Browser UI (6b-ui) — session-cookie auth, server-rendered html/template.
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.postLogout)
	mux.HandleFunc("GET /{$}", s.guardHTML(auth.RoleViewer, s.reposPage))
	mux.HandleFunc("GET /repos/{id}", s.guardHTML(auth.RoleViewer, s.repoPage))
	mux.HandleFunc("POST /repos/{id}/block", s.guardHTML(auth.RoleReviewer, s.htmlBlock))
	mux.HandleFunc("POST /repos/{id}/unblock", s.guardHTML(auth.RoleReviewer, s.htmlUnblock))
	mux.HandleFunc("POST /repos/{id}/overrides", s.guardHTML(auth.RoleReviewer, s.htmlOverride))
	mux.HandleFunc("GET /account", s.guardHTML(auth.RoleViewer, s.accountPage))
	mux.HandleFunc("POST /account/keys", s.guardHTML(auth.RoleViewer, s.accountAddKey))
	mux.HandleFunc("GET /users", s.guardHTML(auth.RoleAdmin, s.usersPage))
	mux.HandleFunc("POST /users", s.guardHTML(auth.RoleAdmin, s.usersCreate))
	mux.HandleFunc("POST /users/{id}/tokens", s.guardHTML(auth.RoleAdmin, s.usersMintToken))
	mux.HandleFunc("POST /users/{id}/keys", s.guardHTML(auth.RoleAdmin, s.usersAddKey))
	return mux
}

// --- auth & rbac ---

type handlerFunc func(w http.ResponseWriter, r *http.Request, id auth.Identity)

// guard authenticates the bearer token and enforces a minimum role before h.
func (s *Server) guard(min auth.Role, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tulli"`)
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if roleRank(id.Role) < roleRank(min) {
			writeErr(w, http.StatusForbidden, "role "+string(id.Role)+" may not perform this action")
			return
		}
		h(w, r, id)
	}
}

// authenticate resolves a request to an identity from either credential source:
// an Authorization: Bearer token (tullictl / API), or the browser session
// cookie (UI). A missing/unknown credential is unauthenticated.
func (s *Server) authenticate(r *http.Request) (auth.Identity, bool) {
	if tok, ok := bearer(r); ok {
		return s.identityFromToken(r.Context(), tok)
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		return s.identityFromSession(r.Context(), c.Value)
	}
	return auth.Anonymous, false
}

// identityFromToken resolves a raw token: the bootstrap admin token
// (constant-time compared) yields a synthetic admin; otherwise the provider.
func (s *Server) identityFromToken(ctx context.Context, tok string) (auth.Identity, bool) {
	if s.adminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.adminToken)) == 1 {
		return bootstrapAdminIdentity(), true
	}
	id, ok, err := s.authr.ByToken(ctx, tok)
	if err != nil {
		s.log.Error("web token lookup failed", "err", err)
		return auth.Anonymous, false
	}
	return id, ok
}

// identityFromSession verifies a session cookie and re-resolves the principal.
// The bootstrap-admin session (sentinel uid) is honoured only while the
// bootstrap token is still configured; a real user's role/kind is re-read from
// the store every request, so demotion/deletion revokes access immediately.
func (s *Server) identityFromSession(ctx context.Context, value string) (auth.Identity, bool) {
	uid, ok := s.sessions.verify(value)
	if !ok {
		return auth.Anonymous, false
	}
	if uid == bootstrapAdminUID {
		if s.adminToken == "" {
			return auth.Anonymous, false // bootstrap disabled → its sessions are void
		}
		return bootstrapAdminIdentity(), true
	}
	id, ok, err := s.store.UserByID(ctx, uid)
	if err != nil {
		s.log.Error("web session user lookup failed", "err", err)
		return auth.Anonymous, false
	}
	return id, ok
}

// bootstrapAdminIdentity is the synthetic principal for the config bootstrap
// token. It has no user row (UserID 0), so account routes reject it.
func bootstrapAdminIdentity() auth.Identity {
	return auth.Identity{Login: "bootstrap-admin", Role: auth.RoleAdmin, Kind: auth.KindHuman}
}

func roleRank(r auth.Role) int {
	switch r {
	case auth.RoleViewer:
		return 1
	case auth.RoleReviewer:
		return 2
	case auth.RoleAdmin:
		return 3
	default:
		return 0
	}
}

func bearer(r *http.Request) (string, bool) {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):], true
	}
	return "", false
}

// --- read handlers ---

type repoView struct {
	ID         int64    `json:"id"`
	MirrorPath string   `json:"mirror_path"`
	Blocked    bool     `json:"blocked"`
	Reason     string   `json:"reason,omitempty"`
	HiddenRefs []string `json:"hidden_refs,omitempty"`
}

func (s *Server) listRepos(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	repos, err := s.store.ListRepos(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list repos failed")
		return
	}
	out := make([]repoView, 0, len(repos))
	for _, rp := range repos {
		v, err := s.store.ResolveVerdict(r.Context(), rp.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "resolve verdict failed")
			return
		}
		out = append(out, repoView{
			ID: rp.ID, MirrorPath: rp.MirrorPath,
			Blocked: v.RepoBlocked, Reason: v.Reason, HiddenRefs: v.HiddenRefs,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type findingView struct {
	Ref         string `json:"ref"`
	Scanner     string `json:"scanner"`
	Severity    string `json:"severity"`
	RuleID      string `json:"rule_id"`
	FilePath    string `json:"file_path"`
	Commit      string `json:"commit"`
	Fingerprint string `json:"fingerprint"`
}

// vulnView is one CVE match on the repo page — informational, never gating.
type vulnView struct {
	Ref          string `json:"ref"`
	PURL         string `json:"purl"`
	Source       string `json:"source"`
	SourceID     string `json:"source_id"`
	Severity     string `json:"severity"`
	Summary      string `json:"summary,omitempty"`
	ToolSeverity string `json:"tool_severity,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
	TriageStatus string `json:"triage_status"`
}

type repoDetail struct {
	repoView
	Findings []findingView `json:"findings"`
	Vulns    []vulnView    `json:"vulnerabilities"`
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	detail, err := s.buildRepoDetail(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "repo lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// buildRepoDetail assembles a repo's verdict + findings — shared by the JSON API
// and the HTML detail page so both show the same data.
func (s *Server) buildRepoDetail(ctx context.Context, id int64) (repoDetail, error) {
	v, err := s.store.ResolveVerdict(ctx, id)
	if err != nil {
		return repoDetail{}, err
	}
	refs, err := s.store.AffectedRefs(ctx, id)
	if err != nil {
		return repoDetail{}, err
	}
	var findings []findingView
	for _, ref := range refs {
		fs, err := s.store.FindingsForRef(ctx, id, ref)
		if err != nil {
			return repoDetail{}, err
		}
		for _, f := range fs {
			findings = append(findings, findingView{
				Ref: ref, Scanner: f.Scanner, Severity: f.Severity, RuleID: f.RuleID,
				FilePath: f.FilePath, Commit: f.Commit, Fingerprint: f.Fingerprint,
			})
		}
	}
	vms, err := s.store.VulnMatchesForRepo(ctx, id)
	if err != nil {
		return repoDetail{}, err
	}
	vulns := make([]vulnView, 0, len(vms))
	for _, m := range vms {
		vulns = append(vulns, vulnView{
			Ref: m.Ref, PURL: m.PURL, Source: m.Source, SourceID: m.SourceID,
			Severity: m.Severity, Summary: m.Summary, ToolSeverity: m.ToolSeverity,
			FixedVersion: m.FixedVersion, TriageStatus: m.TriageStatus,
		})
	}
	return repoDetail{
		repoView: repoView{ID: id, Blocked: v.RepoBlocked, Reason: v.Reason, HiddenRefs: v.HiddenRefs},
		Findings: findings,
		Vulns:    vulns,
	}, nil
}

// --- intent write handlers ---

type blockReq struct {
	Ref    string `json:"ref"` // "" = repo-wide
	Reason string `json:"reason"`
}

func (s *Server) blockRef(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	s.setBlock(w, r, id, true)
}
func (s *Server) unblockRef(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	s.setBlock(w, r, id, false)
}

func (s *Server) setBlock(w http.ResponseWriter, r *http.Request, id auth.Identity, active bool) {
	repoID, ok := pathID(w, r)
	if !ok {
		return
	}
	var req blockReq
	if !decode(w, r, &req) {
		return
	}
	if ie := s.applyBlock(r.Context(), repoID, req.Ref, active, req.Reason, id.Login); ie != nil {
		writeErr(w, ie.code, ie.msg)
		return
	}
	// The write is desired state; the reconciler sweep applies it to disk (§4).
	writeJSON(w, http.StatusAccepted, map[string]any{"applied": "pending reconcile"})
}

type overrideReq struct {
	Ref         string `json:"ref"` // "" = repo-wide
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
}

func (s *Server) addOverride(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	repoID, ok := pathID(w, r)
	if !ok {
		return
	}
	var req overrideReq
	if !decode(w, r, &req) {
		return
	}
	if ie := s.applyOverride(r.Context(), repoID, req.Ref, req.Fingerprint, req.Reason, id.Login); ie != nil {
		writeErr(w, ie.code, ie.msg)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"applied": "pending reconcile"})
}

// intentError carries an HTTP status + message so the shared intent-write
// helpers can serve both the JSON API (writeErr) and the HTML forms (re-render).
type intentError struct {
	code int
	msg  string
}

// applyBlock validates and records a manual block/lift. Single source of the
// rule for both the JSON API and the HTML form so they cannot drift.
func (s *Server) applyBlock(ctx context.Context, repoID int64, ref string, active bool, reason, actor string) *intentError {
	if active && reason == "" {
		return &intentError{http.StatusBadRequest, "a block requires a reason"}
	}
	if err := s.store.InsertManualBlock(ctx, repoID, ref, active, reason, actor); err != nil {
		return &intentError{http.StatusInternalServerError, "write manual block failed"}
	}
	return nil
}

// applyOverride validates and records a finding override (VEX waiver).
func (s *Server) applyOverride(ctx context.Context, repoID int64, ref, fingerprint, reason, actor string) *intentError {
	if fingerprint == "" || reason == "" {
		return &intentError{http.StatusBadRequest, "an override requires a fingerprint and a reason"}
	}
	if err := s.store.InsertOverride(ctx, repoID, ref, fingerprint, reason, actor); err != nil {
		return &intentError{http.StatusInternalServerError, "write override failed"}
	}
	return nil
}

// --- identity handlers (admin) ---

type createUserReq struct {
	Name string    `json:"name"`
	Role auth.Role `json:"role"`
	Kind auth.Kind `json:"kind"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	var req createUserReq
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || roleRank(req.Role) == 0 || !validKind(req.Kind) {
		writeErr(w, http.StatusBadRequest, "name, a valid role (viewer|reviewer|admin) and kind (human|robot) are required")
		return
	}
	uid, err := s.store.InsertUser(r.Context(), req.Name, req.Role, req.Kind)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create user failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": uid})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	uid, ok := pathID(w, r)
	if !ok {
		return
	}
	raw, err := newToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	if err := s.store.InsertToken(r.Context(), uid, auth.HashToken(raw)); err != nil {
		writeErr(w, http.StatusInternalServerError, "store token failed")
		return
	}
	// The raw token is shown once — only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"token": raw})
}

type addKeyReq struct {
	PublicKey string `json:"public_key"` // an authorized_keys line
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	uid, ok := pathID(w, r)
	if !ok {
		return
	}
	var req addKeyReq
	if !decode(w, r, &req) {
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid public key")
		return
	}
	fp := ssh.FingerprintSHA256(pub)
	if err := s.store.InsertSSHKey(r.Context(), uid, fp, req.PublicKey); err != nil {
		writeErr(w, http.StatusInternalServerError, "store key failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"fingerprint": fp})
}

// --- helpers ---

func validKind(k auth.Kind) bool { return k == auth.KindHuman || k == auth.KindRobot }

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// pathIDVal parses the {id} path value without writing a response.
func pathIDVal(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// pathID is the JSON-API variant: it writes a 400 on a bad id.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := pathIDVal(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid id")
	}
	return id, ok
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
