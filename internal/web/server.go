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
	"log/slog"
	"net/http"
	"strconv"

	"golang.org/x/crypto/ssh"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/verdict"
)

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
}

type Server struct {
	store      Store
	authr      auth.Authenticator
	adminToken string // bootstrap admin bearer token (empty = no bootstrap admin)
	log        *slog.Logger
}

func New(store Store, authr auth.Authenticator, adminToken string, log *slog.Logger) *Server {
	return &Server{store: store, authr: authr, adminToken: adminToken, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/repos", s.guard(auth.RoleViewer, s.listRepos))
	mux.HandleFunc("GET /api/repos/{id}", s.guard(auth.RoleViewer, s.getRepo))
	mux.HandleFunc("POST /api/repos/{id}/block", s.guard(auth.RoleReviewer, s.blockRef))
	mux.HandleFunc("POST /api/repos/{id}/unblock", s.guard(auth.RoleReviewer, s.unblockRef))
	mux.HandleFunc("POST /api/repos/{id}/overrides", s.guard(auth.RoleReviewer, s.addOverride))
	mux.HandleFunc("POST /api/users", s.guard(auth.RoleAdmin, s.createUser))
	mux.HandleFunc("POST /api/users/{id}/tokens", s.guard(auth.RoleAdmin, s.createToken))
	mux.HandleFunc("POST /api/users/{id}/keys", s.guard(auth.RoleAdmin, s.addKey))
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

// authenticate resolves the request's bearer token: the bootstrap admin token
// (constant-time compared) yields a synthetic admin; otherwise the token is
// looked up via the provider. A missing/unknown token is unauthenticated.
func (s *Server) authenticate(r *http.Request) (auth.Identity, bool) {
	tok, ok := bearer(r)
	if !ok {
		return auth.Anonymous, false
	}
	if s.adminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.adminToken)) == 1 {
		return auth.Identity{Login: "bootstrap-admin", Role: auth.RoleAdmin, Kind: auth.KindHuman}, true
	}
	id, ok, err := s.authr.ByToken(r.Context(), tok)
	if err != nil {
		s.log.Error("web token lookup failed", "err", err)
		return auth.Anonymous, false
	}
	return id, ok
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

type repoDetail struct {
	repoView
	Findings []findingView `json:"findings"`
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.store.ResolveVerdict(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "resolve verdict failed")
		return
	}
	refs, err := s.store.AffectedRefs(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "affected refs failed")
		return
	}
	var findings []findingView
	for _, ref := range refs {
		fs, err := s.store.FindingsForRef(r.Context(), id, ref)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "findings lookup failed")
			return
		}
		for _, f := range fs {
			findings = append(findings, findingView{
				Ref: ref, Scanner: f.Scanner, Severity: f.Severity, RuleID: f.RuleID,
				FilePath: f.FilePath, Commit: f.Commit, Fingerprint: f.Fingerprint,
			})
		}
	}
	writeJSON(w, http.StatusOK, repoDetail{
		repoView: repoView{ID: id, Blocked: v.RepoBlocked, Reason: v.Reason, HiddenRefs: v.HiddenRefs},
		Findings: findings,
	})
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
	if active && req.Reason == "" {
		writeErr(w, http.StatusBadRequest, "a block requires a reason")
		return
	}
	if err := s.store.InsertManualBlock(r.Context(), repoID, req.Ref, active, req.Reason, id.Login); err != nil {
		writeErr(w, http.StatusInternalServerError, "write manual block failed")
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
	if req.Fingerprint == "" || req.Reason == "" {
		writeErr(w, http.StatusBadRequest, "an override requires a fingerprint and a reason")
		return
	}
	if err := s.store.InsertOverride(r.Context(), repoID, req.Ref, req.Fingerprint, req.Reason, id.Login); err != nil {
		writeErr(w, http.StatusInternalServerError, "write override failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"applied": "pending reconcile"})
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

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
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
