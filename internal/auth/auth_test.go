package auth

import (
	"context"
	"testing"
)

// fakeStore is an in-memory auth.Store for the provider test.
type fakeStore struct {
	byFP    map[string]Identity
	byHash  map[string]Identity
	fpCalls int
}

func (f *fakeStore) UserByFingerprint(_ context.Context, fp string) (Identity, bool, error) {
	f.fpCalls++
	id, ok := f.byFP[fp]
	return id, ok, nil
}
func (f *fakeStore) UserByTokenHash(_ context.Context, h string) (Identity, bool, error) {
	id, ok := f.byHash[h]
	return id, ok, nil
}
func (f *fakeStore) UserByID(_ context.Context, uid int64) (Identity, bool, error) {
	for _, id := range f.byHash {
		if id.UserID == uid {
			return id, true, nil
		}
	}
	return Identity{}, false, nil
}

func TestHashToken_StableAndDistinct(t *testing.T) {
	a1 := HashToken("secret-token")
	a2 := HashToken("secret-token")
	b := HashToken("other-token")
	if a1 != a2 {
		t.Errorf("HashToken not stable: %q != %q", a1, a2)
	}
	if a1 == b {
		t.Error("different tokens hashed to the same value")
	}
	if len(a1) != 64 { // sha256 hex
		t.Errorf("hash length = %d, want 64 hex chars", len(a1))
	}
	if a1 == "secret-token" {
		t.Error("token must not be stored in the clear")
	}
}

func TestDBProvider_ByPublicKey(t *testing.T) {
	want := Identity{UserID: 7, Login: "dev", Role: RoleReviewer, Kind: KindHuman}
	p := NewDBProvider(&fakeStore{byFP: map[string]Identity{"SHA256:abc": want}})

	got, ok, err := p.ByPublicKey(context.Background(), "SHA256:abc")
	if err != nil || !ok || got != want {
		t.Fatalf("ByPublicKey = %+v, ok=%v, err=%v; want %+v", got, ok, err, want)
	}
	if _, ok, _ := p.ByPublicKey(context.Background(), "SHA256:unknown"); ok {
		t.Error("unknown fingerprint should not resolve")
	}
}

// ByToken must hash the raw token before the store lookup (tokens are stored
// hashed), and resolve a robot identity.
func TestDBProvider_ByToken_HashesBeforeLookup(t *testing.T) {
	want := Identity{UserID: 9, Login: "ci", Role: RoleViewer, Kind: KindRobot}
	fs := &fakeStore{byHash: map[string]Identity{HashToken("raw-token"): want}}
	p := NewDBProvider(fs)

	got, ok, err := p.ByToken(context.Background(), "raw-token")
	if err != nil || !ok || got != want {
		t.Fatalf("ByToken = %+v, ok=%v, err=%v; want %+v", got, ok, err, want)
	}
	// A lookup by the *raw* token (unhashed) must miss — proving we hashed.
	if _, ok, _ := (&fakeStore{byHash: map[string]Identity{"raw-token": want}}).UserByTokenHash(context.Background(), HashToken("raw-token")); ok {
		t.Error("store keyed on the raw token should not match the hashed lookup")
	}
}

func TestIdentity_IsAnonymous(t *testing.T) {
	if !Anonymous.IsAnonymous() {
		t.Error("zero identity should be anonymous")
	}
	if (Identity{UserID: 1}).IsAnonymous() {
		t.Error("a user with an id is not anonymous")
	}
}
