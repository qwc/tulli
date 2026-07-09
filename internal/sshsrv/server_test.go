package sshsrv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeGate mimics core.Gatekeeper for routing tests: it refuses receive-pack
// (the read-only invariant) and otherwise returns the programmed admission.
type fakeGate struct {
	adm      core.Admission
	err      error
	gotRef   git.RepoRef
	gotVerb  string
	admitted bool
	finished *core.Access
}

func (f *fakeGate) Admit(_ context.Context, ref git.RepoRef, verb string) (core.Admission, error) {
	f.admitted = true
	f.gotRef, f.gotVerb = ref, verb
	if verb == git.VerbReceivePack {
		return core.Admission{Allowed: false, Verb: verb, BlockMsg: "tulli is a read-only proxy; push is not supported"}, nil
	}
	return f.adm, f.err
}

func (f *fakeGate) FinishAudit(_ context.Context, a core.Access) { f.finished = &a }

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startServer runs a Server on a loopback port and returns a connected client.
func startServer(t *testing.T, gate Gate) *ssh.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := New(gate, testSigner(t), discardLogger())
	go func() { _ = srv.Serve(ctx, ln) }()

	clientCfg := &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(testSigner(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// runExec opens a session, runs command, and returns its stderr and exit code
// (-1 if the command could not be started / no exit status).
func runExec(t *testing.T, client *ssh.Client, command string) (stderr string, code int) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	var buf bytes.Buffer
	sess.Stderr = &buf
	err = sess.Run(command)
	code = 0
	if err != nil {
		if ee, ok := err.(*ssh.ExitError); ok {
			code = ee.ExitStatus()
		} else {
			code = -1
		}
	}
	return buf.String(), code
}

func TestSSH_BlockedWritesStderrAndExitsNonZero(t *testing.T) {
	gate := &fakeGate{adm: core.Admission{Allowed: false, BlockMsg: "tulli: repo QUARANTINED — 3 HIGH secrets (gitleaks)"}}
	client := startServer(t, gate)

	stderr, code := runExec(t, client, "git-upload-pack '/github.com/acme/widget'")
	if code == 0 {
		t.Errorf("blocked clone should exit non-zero, got %d", code)
	}
	if !strings.Contains(stderr, "QUARANTINED") || !strings.Contains(stderr, "gitleaks") {
		t.Errorf("stderr missing block message: %q", stderr)
	}
	if !gate.admitted || gate.gotVerb != git.VerbUploadPack {
		t.Errorf("gate got verb %q (admitted=%v)", gate.gotVerb, gate.admitted)
	}
	if gate.gotRef.Host != "github.com" || gate.gotRef.Path != "acme/widget" {
		t.Errorf("gate got ref %v", gate.gotRef)
	}
	if gate.finished != nil {
		t.Error("a blocked request must not be audited as served")
	}
}

func TestSSH_ReadOnlyRefusesReceivePack(t *testing.T) {
	gate := &fakeGate{} // Admit refuses receive-pack itself
	client := startServer(t, gate)

	stderr, code := runExec(t, client, "git-receive-pack '/github.com/acme/widget'")
	if code == 0 {
		t.Errorf("receive-pack should be refused, got exit %d", code)
	}
	if !strings.Contains(strings.ToLower(stderr), "read-only") {
		t.Errorf("stderr missing read-only refusal: %q", stderr)
	}
}

func TestSSH_UnsupportedCommandRejected(t *testing.T) {
	gate := &fakeGate{}
	client := startServer(t, gate)

	stderr, code := runExec(t, client, "bash -i")
	if code == 0 {
		t.Errorf("interactive shell should be rejected, got exit %d", code)
	}
	if !strings.Contains(stderr, "unsupported command") {
		t.Errorf("stderr missing rejection: %q", stderr)
	}
	if gate.admitted {
		t.Error("a malformed command must be rejected before the gate is consulted")
	}
}
