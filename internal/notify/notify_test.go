package notify

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"codeberg.org/qwc/tulli/internal/core"
)

func TestLogNotifier_Deliver(t *testing.T) {
	var buf bytes.Buffer
	n := NewLogNotifier(slog.New(slog.NewTextHandler(&buf, nil)))
	err := n.Deliver(context.Background(), Notice{
		Repo: "/m/app.git", Refs: []string{"refs/heads/evil"}, Reason: "secret",
		Recipients: []core.Recipient{{UserID: 1, Login: "alice"}, {UserID: 2, Login: "bob"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"QUARANTINE NOTICE", "/m/app.git", "refs/heads/evil", "alice", "bob"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q in:\n%s", want, out)
		}
	}
}

func TestPayloadDescriptor(t *testing.T) {
	if got := PayloadDescriptor(Notice{Repo: "r", RepoWide: true}); got != "log:quarantine/r/(repo-wide)" {
		t.Errorf("repo-wide descriptor = %q", got)
	}
	if got := PayloadDescriptor(Notice{Repo: "r", Refs: []string{"a", "b"}}); got != "log:quarantine/r/a,b" {
		t.Errorf("ref descriptor = %q", got)
	}
}
