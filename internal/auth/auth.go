// Package auth is tulli's identity & access seam (spec §5, stage 6a). It turns a
// transport credential — an SSH public key or an HTTP token — into an Identity,
// behind a provider interface so the backend is pluggable: the local database is
// the first provider; LDAP/OIDC slot in behind the same Authenticator later
// (a directory provider resolving the same credentials, or a composite chaining
// several). Identity is resolved by the transport adapter and passed into the
// core hallway (Admit), keeping the hallway transport-agnostic.
//
// Roles are carried here now and enforced by the web API in 6b; the git-serving
// path does not authorize by role (public FOSS is anonymously fetchable) — it
// only attributes the fetch to a user for the audit trail and precise notify.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Role is the minimal authorization level (migration 00004). viewer reads;
// reviewer triages/overrides; admin manages users and repo-wide blocks. Full
// RBAC (per-repo ownership, scopes) deepens this in 6g.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleReviewer Role = "reviewer"
	RoleAdmin    Role = "admin"
)

// Kind distinguishes a human from a robot (CI) principal. A robot authenticates
// only by key/token — never an interactive/LDAP login (stage 6f).
type Kind string

const (
	KindHuman Kind = "human"
	KindRobot Kind = "robot"
)

// Identity is who a request is, resolved from its credential. The zero value is
// anonymous — permitted for HTTP fetches of public repos, never for SSH.
type Identity struct {
	UserID int64
	Login  string
	Role   Role
	Kind   Kind
}

// Anonymous is the unauthenticated principal.
var Anonymous = Identity{}

// IsAnonymous reports whether no user was resolved.
func (i Identity) IsAnonymous() bool { return i.UserID == 0 }

// Store is the lookup seam over users/ssh_keys/tokens (implemented by
// internal/store.Mem and internal/store/pg). Both lookups join through to the
// user's role/kind so a single query yields a full Identity.
type Store interface {
	// UserByFingerprint resolves an SSH public-key fingerprint (SHA256) to an
	// identity; ok is false when the key is unregistered.
	UserByFingerprint(ctx context.Context, fingerprint string) (id Identity, ok bool, err error)
	// UserByTokenHash resolves a hashed HTTP token to an identity; ok is false
	// when the token is unknown.
	UserByTokenHash(ctx context.Context, tokenHash string) (id Identity, ok bool, err error)
	// UserByID resolves a user id to a current identity; ok is false when the
	// user is gone. The web re-resolves the session principal through this on
	// every request, so a demoted or deleted user loses access immediately
	// (revocation) rather than at cookie expiry.
	UserByID(ctx context.Context, userID int64) (id Identity, ok bool, err error)
}

// Authenticator resolves transport credentials to an Identity. Adapters depend on
// this interface, not a concrete backend, so LDAP/OIDC providers drop in later.
type Authenticator interface {
	// ByPublicKey resolves an SSH public-key fingerprint (ssh.FingerprintSHA256).
	ByPublicKey(ctx context.Context, fingerprint string) (id Identity, ok bool, err error)
	// ByToken resolves a raw HTTP bearer/basic token (hashed internally).
	ByToken(ctx context.Context, token string) (id Identity, ok bool, err error)
}

// DBProvider authenticates against the local database (the first provider).
type DBProvider struct{ store Store }

// NewDBProvider builds the local-database Authenticator.
func NewDBProvider(store Store) *DBProvider { return &DBProvider{store: store} }

var _ Authenticator = (*DBProvider)(nil)

func (p *DBProvider) ByPublicKey(ctx context.Context, fingerprint string) (Identity, bool, error) {
	return p.store.UserByFingerprint(ctx, fingerprint)
}

func (p *DBProvider) ByToken(ctx context.Context, token string) (Identity, bool, error) {
	return p.store.UserByTokenHash(ctx, HashToken(token))
}

// HashToken hashes a bearer token for storage and lookup. Tokens are
// high-entropy random secrets, so a fast SHA-256 (indexable, constant-work) is
// the right primitive — not a password KDF, which would defeat the DB lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
