package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// bootstrapAdminUID is the sentinel user id carried by a session minted from the
// bootstrap admin token. It is negative so it can never collide with a real
// users.id (which is a positive bigserial), and it is only honoured while the
// bootstrap token is still configured — see authenticate().
const bootstrapAdminUID int64 = -1

// sessions issues and verifies the browser session cookie. The cookie is a
// stateless, HMAC-signed assertion "this is user N until T" — it carries no
// role, so role/kind are re-resolved from the store on every request and a
// demoted or deleted user loses access immediately (revocation). Being
// stateless (no server-side table), any carved-out web replica sharing the
// secret validates the same cookie. This is deliberately a small seam: a
// DB-backed revocable session store can replace it later without touching the
// handlers.
type sessions struct {
	secret []byte
	ttl    time.Duration
}

func newSessions(secret []byte, ttl time.Duration) *sessions {
	return &sessions{secret: secret, ttl: ttl}
}

// issue returns a signed cookie value asserting uid, valid for the TTL, plus its
// expiry time (for the cookie's Expires/Max-Age).
func (s *sessions) issue(uid int64) (value string, expiry time.Time) {
	expiry = time.Now().Add(s.ttl)
	payload := strconv.FormatInt(uid, 10) + ":" + strconv.FormatInt(expiry.Unix(), 10)
	return payload + "." + s.sign(payload), expiry
}

// verify checks the signature and expiry, returning the asserted uid.
func (s *sessions) verify(value string) (uid int64, ok bool) {
	payload, sig, found := strings.Cut(value, ".")
	if !found {
		return 0, false
	}
	if !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return 0, false
	}
	uidStr, expStr, found := strings.Cut(payload, ":")
	if !found {
		return 0, false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return 0, false
	}
	uid, err = strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return uid, true
}

func (s *sessions) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
