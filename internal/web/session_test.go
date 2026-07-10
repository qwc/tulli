package web

import (
	"testing"
	"time"
)

func TestSession_RoundTrip(t *testing.T) {
	s := newSessions([]byte("secret"), time.Hour)
	val, exp := s.issue(42)
	if !exp.After(time.Now()) {
		t.Fatalf("expiry not in the future: %v", exp)
	}
	uid, ok := s.verify(val)
	if !ok || uid != 42 {
		t.Fatalf("verify = (%d, %v), want (42, true)", uid, ok)
	}
}

func TestSession_TamperedSignatureRejected(t *testing.T) {
	s := newSessions([]byte("secret"), time.Hour)
	val, _ := s.issue(7)
	// Flip the last character of the signature.
	tampered := val[:len(val)-1] + "x"
	if _, ok := s.verify(tampered); ok {
		t.Fatal("verify accepted a tampered cookie")
	}
}

func TestSession_WrongSecretRejected(t *testing.T) {
	val, _ := newSessions([]byte("secret-a"), time.Hour).issue(7)
	if _, ok := newSessions([]byte("secret-b"), time.Hour).verify(val); ok {
		t.Fatal("verify accepted a cookie signed with a different secret")
	}
}

func TestSession_ExpiredRejected(t *testing.T) {
	s := newSessions([]byte("secret"), -time.Second) // already expired
	val, _ := s.issue(7)
	if _, ok := s.verify(val); ok {
		t.Fatal("verify accepted an expired cookie")
	}
}

func TestSession_GarbageRejected(t *testing.T) {
	s := newSessions([]byte("secret"), time.Hour)
	for _, v := range []string{"", "nodot", "a.b.c", "notanum:123.sig"} {
		if _, ok := s.verify(v); ok {
			t.Fatalf("verify accepted garbage %q", v)
		}
	}
}
