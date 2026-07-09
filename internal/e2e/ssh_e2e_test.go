package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
	"codeberg.org/qwc/tulli/internal/mirror"
	"codeberg.org/qwc/tulli/internal/scan"
	"codeberg.org/qwc/tulli/internal/sshsrv"
	"codeberg.org/qwc/tulli/internal/store"
)

// sshStack is the wired system under test, reached over the SSH door.
type sshStack struct {
	addr string
	st   *store.Mem
}

// newSSHStack wires the real core hallway behind an in-process SSH server on a
// loopback port. It reuses the same gate/mirror/store the HTTP stack does — the
// SSH server is just a second transport. Skips if git is unavailable.
func newSSHStack(t *testing.T, upstreamBase string) *sshStack {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mirrors := filepath.Join(t.TempDir(), "mirrors")
	mir := git.NewMirror(mirrors, upstreamBase, discardLogger())
	st := store.NewMem()
	reconciler := mirror.NewReconciler(st, discardLogger())
	worker := scan.NewWorker(noopScanner{}, st, git.RefsContaining, reconciler, discardLogger())
	go worker.Run(ctx)
	gate := core.New(mir, st, worker, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := sshsrv.New(gate, testHostKey(t), discardLogger())
	go func() { _ = srv.Serve(ctx, ln) }() // ctx cancel (cleanup) closes ln
	return &sshStack{addr: ln.Addr().String(), st: st}
}

func testHostKey(t *testing.T) ssh.Signer {
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

// clientKeyFile writes a throwaway OpenSSH private key and returns its path (the
// server is anonymous — any key is accepted — but the git ssh client needs one).
func clientKeyFile(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sshGit runs a git subcommand against the SSH proxy, wiring GIT_SSH_COMMAND to a
// throwaway key and disabling host-key checking (loopback test server).
func sshGit(t *testing.T, s *sshStack, key string, args ...string) (string, error) {
	t.Helper()
	_, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		t.Fatal(err)
	}
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -p %s", key, port)
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+sshCmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sshURL builds the clone URL for repoPath through the proxy.
func (s *sshStack) url(repoPath string) string {
	host, port, _ := net.SplitHostPort(s.addr)
	return fmt.Sprintf("ssh://git@%s:%s/%s", host, port, repoPath)
}

func TestE2E_SSH_CloneThroughProxy(t *testing.T) {
	up := t.TempDir()
	makeUpstream(t, filepath.Join(up, "example.com/acme/widget"), "hello ssh\n")
	s := newSSHStack(t, "file://"+up)
	key := clientKeyFile(t)

	dst := filepath.Join(t.TempDir(), "clone")
	if out, err := sshGit(t, s, key, "clone", "-q", s.url("example.com/acme/widget"), dst); err != nil {
		t.Fatalf("ssh clone failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(dst, "README.md"))
	if err != nil || string(got) != "hello ssh\n" {
		t.Fatalf("cloned README = %q, err %v", got, err)
	}
	// Audit trail: the served fetch was recorded against the repo.
	if s.st.RepoCount() != 1 {
		t.Errorf("audit RepoCount = %d, want 1", s.st.RepoCount())
	}
	var served bool
	for _, e := range s.st.Events() {
		if e.Bytes > 0 && e.RepoID != 0 {
			served = true
		}
	}
	if !served {
		t.Errorf("expected an audited SSH fetch with bytes>0; got %+v", s.st.Events())
	}
}

func TestE2E_SSH_RepoWideQuarantineBlocksClone(t *testing.T) {
	up := t.TempDir()
	makeUpstream(t, filepath.Join(up, "example.com/acme/widget"), "hello\n")
	s := newSSHStack(t, "file://"+up)
	key := clientKeyFile(t)
	base := "file://" + up

	// First clone registers the repo (assigns its id).
	if out, err := sshGit(t, s, key, "clone", "-q", s.url("example.com/acme/widget"), filepath.Join(t.TempDir(), "before")); err != nil {
		t.Fatalf("initial ssh clone failed: %v\n%s", err, out)
	}
	ref := git.RepoRef{Host: "example.com", Path: "acme/widget"}
	id, ok := s.st.RepoID(ref.UpstreamURL(base))
	if !ok {
		t.Fatal("repo not registered after first clone")
	}
	s.st.SetVerdict(id, "", "QUARANTINED", "3 HIGH secrets (gitleaks)")

	// A subsequent clone must fail with our operator message on remote stderr.
	out, err := sshGit(t, s, key, "clone", "-q", s.url("example.com/acme/widget"), filepath.Join(t.TempDir(), "after"))
	if err == nil {
		t.Fatalf("clone of a quarantined repo should fail; output:\n%s", out)
	}
	if !strings.Contains(out, "QUARANTINED") || !strings.Contains(out, "gitleaks") {
		t.Fatalf("clone failed but without our block message:\n%s", out)
	}
}

func TestE2E_SSH_RefLevelQuarantineHidesRef(t *testing.T) {
	up := t.TempDir()
	repo := filepath.Join(up, "example.com/acme/widget")
	makeUpstream(t, repo, "clean main\n")
	makeUpstreamBranch(t, repo, "evil", "leaked secret\n")
	s := newSSHStack(t, "file://"+up)
	key := clientKeyFile(t)
	base := "file://" + up
	url := s.url("example.com/acme/widget")

	// Register the repo (both refs present before quarantine).
	out, err := sshGit(t, s, key, "ls-remote", url)
	if err != nil {
		t.Fatalf("ls-remote failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "refs/heads/evil") || !strings.Contains(out, "refs/heads/main") {
		t.Fatalf("expected both refs advertised, got:\n%s", out)
	}

	ref := git.RepoRef{Host: "example.com", Path: "acme/widget"}
	id, ok := s.st.RepoID(ref.UpstreamURL(base))
	if !ok {
		t.Fatal("repo not registered")
	}
	s.st.SetVerdict(id, "refs/heads/evil", "QUARANTINED", "secret on this branch")

	// evil is now hidden from the advertisement; main stays.
	out, err = sshGit(t, s, key, "ls-remote", url)
	if err != nil {
		t.Fatalf("ls-remote after quarantine failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "refs/heads/evil") {
		t.Errorf("quarantined ref refs/heads/evil must not be advertised:\n%s", out)
	}
	if !strings.Contains(out, "refs/heads/main") {
		t.Errorf("clean ref refs/heads/main must stay advertised:\n%s", out)
	}
	// A full clone succeeds and omits the hidden ref.
	if out, err := sshGit(t, s, key, "clone", "-q", url, filepath.Join(t.TempDir(), "c")); err != nil {
		t.Fatalf("clone after ref quarantine failed: %v\n%s", err, out)
	}
}
