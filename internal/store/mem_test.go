package store

import (
	"context"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
)

// Mem must satisfy the core.Store seam.
var _ core.Store = (*Mem)(nil)

func TestMem_UpsertRepoIdempotent(t *testing.T) {
	m := NewMem()
	ctx := context.Background()

	id1, _ := m.UpsertRepo(ctx, "https://github.com/o/r", "/m/r.git")
	id2, _ := m.UpsertRepo(ctx, "https://github.com/o/r", "/m/r.git")
	if id1 != id2 {
		t.Fatalf("same upstream gave different ids: %d vs %d", id1, id2)
	}
	id3, _ := m.UpsertRepo(ctx, "https://github.com/o/other", "/m/other.git")
	if id3 == id1 {
		t.Fatalf("distinct upstreams must get distinct ids (both %d)", id1)
	}
	if m.RepoCount() != 2 {
		t.Fatalf("RepoCount = %d, want 2", m.RepoCount())
	}
}

func TestMem_InsertAccessEvent(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	m.InsertAccessEvent(ctx, core.Access{RepoID: 1, SourceIP: "1.2.3.4", Status: 200, Bytes: 10})
	m.InsertAccessEvent(ctx, core.Access{RepoID: 1, SourceIP: "5.6.7.8", Status: 200, Bytes: 20})

	ev := m.Events()
	if len(ev) != 2 || ev[0].Bytes != 10 || ev[1].SourceIP != "5.6.7.8" {
		t.Fatalf("events = %+v", ev)
	}
	// Events must return a copy — mutating it must not affect the store.
	ev[0].Bytes = 999
	if m.Events()[0].Bytes != 10 {
		t.Fatal("Events() must return a copy, not the backing slice")
	}
}
