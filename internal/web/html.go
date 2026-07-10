package web

import (
	"bytes"
	"context"
	"embed"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"codeberg.org/qwc/tulli/internal/auth"
)

// sessionCookieName is the browser session cookie. It carries only a signed
// {uid, exp}; see session.go.
const sessionCookieName = "tulli_session"

//go:embed templates/*.html
var templateFS embed.FS

// parseTemplates builds one template set per page: the shared base layout plus
// that page's content, so each page can define its own {{"content"}} block
// without name collisions. html/template auto-escapes — findings carry
// untrusted upstream data (paths, rule text), so this is load-bearing.
func parseTemplates() map[string]*template.Template {
	funcs := template.FuncMap{
		"canReview": func(r auth.Role) bool { return roleRank(r) >= roleRank(auth.RoleReviewer) },
		"canAdmin":  func(r auth.Role) bool { return roleRank(r) >= roleRank(auth.RoleAdmin) },
		"short": func(s string) string { // short commit sha for display
			if len(s) > 10 {
				return s[:10]
			}
			return s
		},
	}
	pages := []string{"login", "repos", "repo", "account", "users", "forbidden"}
	out := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		out[p] = template.Must(template.New(p).Funcs(funcs).ParseFS(templateFS, "templates/base.html", "templates/"+p+".html"))
	}
	return out
}

// page is the wrapper handed to every template: the current principal (for the
// nav) plus the page-specific view in Data.
type page struct {
	Me    auth.Identity
	Title string
	Data  any
}

func (s *Server) render(w http.ResponseWriter, status int, name string, me auth.Identity, title string, data any) {
	t, ok := s.tmpl[name]
	if !ok {
		s.log.Error("unknown template", "name", name)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	// Render into a buffer first so a template error yields a clean 500 rather
	// than a half-written 200.
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base.html", page{Me: me, Title: title, Data: data}); err != nil {
		s.log.Error("template render failed", "name", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// --- session cookie helpers ---

func (s *Server) setSession(w http.ResponseWriter, uid int64) {
	value, expiry := s.sessions.issue(uid)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- HTML auth guard (redirect to login instead of a JSON 401) ---

// guardHTML authenticates via cookie/bearer and enforces a minimum role,
// redirecting unauthenticated browsers to /login and rendering a 403 page when
// the role is insufficient. CSRF defence for the prototype is the SameSite=Lax
// session cookie (blocks cross-site POST); a per-session HMAC CSRF token should
// be added before leaving prototype phase.
func (s *Server) guardHTML(min auth.Role, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.authenticate(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if roleRank(id.Role) < roleRank(min) {
			s.render(w, http.StatusForbidden, "forbidden", id, "Forbidden", min)
			return
		}
		h(w, r, id)
	}
}

// --- login / logout ---

type loginView struct{ Error string }

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", auth.Anonymous, "Sign in", loginView{})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.FormValue("token"))
	uid, ok := s.loginUID(r, tok)
	if !ok {
		s.render(w, http.StatusUnauthorized, "login", auth.Anonymous, "Sign in",
			loginView{Error: "Invalid or unknown token."})
		return
	}
	s.setSession(w, uid)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// loginUID resolves a login token to the uid to store in the session: the
// bootstrap sentinel for the config admin token, or the user's id via the
// provider. Mirrors identityFromToken's two branches.
func (s *Server) loginUID(r *http.Request, tok string) (int64, bool) {
	if tok == "" {
		return 0, false
	}
	if id, ok := s.identityFromToken(r.Context(), tok); ok {
		if id.UserID == 0 { // synthetic bootstrap admin
			return bootstrapAdminUID, true
		}
		return id.UserID, true
	}
	return 0, false
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- repo list / detail ---

type reposView struct{ Repos []repoView }

func (s *Server) reposPage(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	repos, err := s.store.ListRepos(r.Context())
	if err != nil {
		s.render(w, http.StatusInternalServerError, "repos", me, "Repos", reposView{})
		return
	}
	out := make([]repoView, 0, len(repos))
	for _, rp := range repos {
		v, err := s.store.ResolveVerdict(r.Context(), rp.ID)
		if err != nil {
			s.log.Error("resolve verdict failed", "repo", rp.ID, "err", err)
			continue
		}
		out = append(out, repoView{
			ID: rp.ID, MirrorPath: rp.MirrorPath,
			Blocked: v.RepoBlocked, Reason: v.Reason, HiddenRefs: v.HiddenRefs,
		})
	}
	s.render(w, http.StatusOK, "repos", me, "Repos", reposView{Repos: out})
}

// repoPageView is the detail page: the repo verdict + findings, flattened (no
// embedding) for straightforward template field access, plus an optional form
// error to re-render after a rejected block/override.
type repoPageView struct {
	ID         int64
	Blocked    bool
	Reason     string
	HiddenRefs []string
	Findings   []findingView
	Vulns      []vulnView
	Error      string
	CanEdit    bool // reviewer+ sees the action forms
}

func (s *Server) repoPage(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	id, ok := pathIDVal(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.renderRepo(w, r.Context(), me, id, "", http.StatusOK)
}

// renderRepo builds and renders the detail page (shared by GET and by the form
// handlers that re-render on error).
func (s *Server) renderRepo(w http.ResponseWriter, ctx context.Context, me auth.Identity, id int64, formErr string, status int) {
	detail, err := s.buildRepoDetail(ctx, id)
	if err != nil {
		s.log.Error("repo detail failed", "repo", id, "err", err)
		http.Error(w, "repo lookup failed", http.StatusInternalServerError)
		return
	}
	s.render(w, status, "repo", me, "Repo", repoPageView{
		ID:         detail.ID,
		Blocked:    detail.Blocked,
		Reason:     detail.Reason,
		HiddenRefs: detail.HiddenRefs,
		Findings:   detail.Findings,
		Vulns:      detail.Vulns,
		Error:      formErr,
		CanEdit:    roleRank(me.Role) >= roleRank(auth.RoleReviewer),
	})
}

func (s *Server) htmlBlock(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	s.htmlSetBlock(w, r, me, true)
}
func (s *Server) htmlUnblock(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	s.htmlSetBlock(w, r, me, false)
}

func (s *Server) htmlSetBlock(w http.ResponseWriter, r *http.Request, me auth.Identity, active bool) {
	id, ok := pathIDVal(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ref := strings.TrimSpace(r.FormValue("ref"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if ie := s.applyBlock(r.Context(), id, ref, active, reason, me.Login); ie != nil {
		s.renderRepo(w, r.Context(), me, id, ie.msg, ie.code)
		return
	}
	http.Redirect(w, r, repoPath(id), http.StatusSeeOther)
}

func (s *Server) htmlOverride(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	id, ok := pathIDVal(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ref := strings.TrimSpace(r.FormValue("ref"))
	fingerprint := strings.TrimSpace(r.FormValue("fingerprint"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if ie := s.applyOverride(r.Context(), id, ref, fingerprint, reason, me.Login); ie != nil {
		s.renderRepo(w, r.Context(), me, id, ie.msg, ie.code)
		return
	}
	http.Redirect(w, r, repoPath(id), http.StatusSeeOther)
}

// --- account (self-service key upload) ---

type accountView struct {
	Error   string
	Message string
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	s.render(w, http.StatusOK, "account", me, "Account", accountView{})
}

func (s *Server) accountAddKey(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	if me.UserID == 0 {
		s.render(w, http.StatusForbidden, "account", me, "Account",
			accountView{Error: "The bootstrap admin has no stored account; create a real user to upload keys."})
		return
	}
	raw := strings.TrimSpace(r.FormValue("public_key"))
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		s.render(w, http.StatusBadRequest, "account", me, "Account",
			accountView{Error: "That does not look like a valid SSH public key."})
		return
	}
	fp := ssh.FingerprintSHA256(pub)
	if err := s.store.InsertSSHKey(r.Context(), me.UserID, fp, raw); err != nil {
		s.render(w, http.StatusInternalServerError, "account", me, "Account",
			accountView{Error: "Storing the key failed."})
		return
	}
	s.render(w, http.StatusOK, "account", me, "Account",
		accountView{Message: "Key registered: " + fp})
}

// --- admin: users ---

type usersView struct {
	Users       []auth.Identity
	Error       string
	MintedToken string // shown once, right after minting
	MintedFor   string
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	s.renderUsers(w, r.Context(), me, usersView{})
}

func (s *Server) renderUsers(w http.ResponseWriter, ctx context.Context, me auth.Identity, v usersView) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		s.log.Error("list users failed", "err", err)
		http.Error(w, "list users failed", http.StatusInternalServerError)
		return
	}
	v.Users = users
	status := http.StatusOK
	if v.Error != "" {
		status = http.StatusBadRequest
	}
	s.render(w, status, "users", me, "Users", v)
}

func (s *Server) usersCreate(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	name := strings.TrimSpace(r.FormValue("name"))
	role := auth.Role(r.FormValue("role"))
	kind := auth.Kind(r.FormValue("kind"))
	if name == "" || roleRank(role) == 0 || !validKind(kind) {
		s.renderUsers(w, r.Context(), me, usersView{Error: "A name, a valid role and a valid kind are required."})
		return
	}
	if _, err := s.store.InsertUser(r.Context(), name, role, kind); err != nil {
		s.renderUsers(w, r.Context(), me, usersView{Error: "Creating the user failed."})
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) usersMintToken(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	uid, ok := pathIDVal(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw, err := newToken()
	if err != nil {
		s.renderUsers(w, r.Context(), me, usersView{Error: "Token generation failed."})
		return
	}
	if err := s.store.InsertToken(r.Context(), uid, auth.HashToken(raw)); err != nil {
		s.renderUsers(w, r.Context(), me, usersView{Error: "Storing the token failed."})
		return
	}
	// The raw token is displayed once; only its hash is stored.
	name := strings.TrimSpace(r.FormValue("login"))
	s.renderUsers(w, r.Context(), me, usersView{MintedToken: raw, MintedFor: name})
}

func (s *Server) usersAddKey(w http.ResponseWriter, r *http.Request, me auth.Identity) {
	uid, ok := pathIDVal(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimSpace(r.FormValue("public_key"))
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		s.renderUsers(w, r.Context(), me, usersView{Error: "That does not look like a valid SSH public key."})
		return
	}
	if err := s.store.InsertSSHKey(r.Context(), uid, ssh.FingerprintSHA256(pub), raw); err != nil {
		s.renderUsers(w, r.Context(), me, usersView{Error: "Storing the key failed."})
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// --- small helpers ---

func repoPath(id int64) string { return "/repos/" + strconv.FormatInt(id, 10) }
