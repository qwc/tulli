// Package sshsrv is the SSH door onto the core hallway — the second transport
// alongside internal/httpsrv, sharing the same gate. A git SSH client presents a
// public key, then sends an exec request like `git-upload-pack '/host/owner/repo'`;
// we parse it, run the same Admit (resolve → ensure → gate), and on success exec
// `git upload-pack <mirror>` wired to the channel. A block is written to the
// session's stderr with a non-zero exit (git surfaces it as `remote: <msg>`,
// spec §3.3) — the SSH equivalent of the HTTP ERR pkt-line.
//
// Stage 5 is anonymous: any key is accepted (public FOSS, like HTTP today) and
// its fingerprint is recorded for the audit trail. Real pubkey→user lookup and
// rejecting unknown keys land in stage 6 behind the auth seam; that is the one
// line in PublicKeyCallback that changes.
package sshsrv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/crypto/ssh"

	"codeberg.org/qwc/tulli/internal/auth"
	"codeberg.org/qwc/tulli/internal/core"
	"codeberg.org/qwc/tulli/internal/git"
)

// Gate is the hallway seam (implemented by *core.Gatekeeper) — identical to the
// one httpsrv depends on, so the routing is tested with a fake.
type Gate interface {
	Admit(ctx context.Context, ref git.RepoRef, verb string, id auth.Identity) (core.Admission, error)
	FinishAudit(ctx context.Context, a core.Access)
}

type Server struct {
	gate Gate
	cfg  *ssh.ServerConfig
	log  *slog.Logger
}

// New builds an SSH server that admits through gate and serves from hostKey.
// Identity policy (stage 6a): SSH is authenticated — the presented public key
// must resolve to a known user (human or robot); an unregistered key is rejected
// at the handshake. (HTTP, by contrast, allows anonymous fetches.)
func New(gate Gate, authr auth.Authenticator, hostKey ssh.Signer, log *slog.Logger) *Server {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			id, ok, err := authr.ByPublicKey(context.Background(), fp)
			if err != nil {
				return nil, fmt.Errorf("ssh auth lookup: %w", err)
			}
			if !ok {
				return nil, fmt.Errorf("unregistered ssh key %s", fp)
			}
			return &ssh.Permissions{Extensions: identityExtensions(id)}, nil
		},
	}
	cfg.AddHostKey(hostKey)
	return &Server{gate: gate, cfg: cfg, log: log}
}

// identityExtensions carries the resolved identity across the handshake into the
// session handler (ssh.Permissions.Extensions is string-only).
func identityExtensions(id auth.Identity) map[string]string {
	return map[string]string{
		"tulli-uid":   strconv.FormatInt(id.UserID, 10),
		"tulli-login": id.Login,
		"tulli-role":  string(id.Role),
		"tulli-kind":  string(id.Kind),
	}
}

func identityFromPermissions(p *ssh.Permissions) auth.Identity {
	if p == nil {
		return auth.Anonymous
	}
	uid, _ := strconv.ParseInt(p.Extensions["tulli-uid"], 10, 64)
	return auth.Identity{
		UserID: uid,
		Login:  p.Extensions["tulli-login"],
		Role:   auth.Role(p.Extensions["tulli-role"]),
		Kind:   auth.Kind(p.Extensions["tulli-kind"]),
	}
}

// ListenAndServe listens on addr until ctx is cancelled (which closes the
// listener and unblocks Accept).
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, s.cfg)
	if err != nil {
		s.log.Debug("ssh handshake failed", "remote", nConn.RemoteAddr().String(), "err", err)
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs) // no global requests are honoured

	srcIP := remoteIP(sconn.RemoteAddr())
	id := identityFromPermissions(sconn.Permissions)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			s.log.Debug("channel accept failed", "err", err)
			continue
		}
		go s.handleSession(ctx, ch, chReqs, srcIP, id)
	}
}

// handleSession consumes a session's requests: it captures GIT_PROTOCOL (for
// protocol v2) and dispatches the single exec that git sends. Interactive
// requests (shell/pty) are refused — this is not a login server.
func (s *Server) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, srcIP string, id auth.Identity) {
	defer ch.Close()
	var gitProtocol string
	for req := range reqs {
		switch req.Type {
		case "env":
			var e struct{ Name, Value string }
			if err := ssh.Unmarshal(req.Payload, &e); err == nil && e.Name == "GIT_PROTOCOL" {
				gitProtocol = e.Value
			}
			reply(req, true)
		case "exec":
			var e struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &e); err != nil {
				reply(req, false)
				return
			}
			reply(req, true)
			s.runGit(ctx, ch, e.Command, gitProtocol, srcIP, id)
			return // exactly one exec per git session
		default:
			reply(req, false) // shell, pty-req, subsystem, … not supported
		}
	}
}

// runGit parses the git command, admits it through the hallway, and either
// streams `git upload-pack` to the channel or reports the block on stderr.
func (s *Server) runGit(ctx context.Context, ch ssh.Channel, command, gitProtocol, srcIP string, id auth.Identity) {
	ref, verb, err := git.ParseSSHCommand(command)
	if err != nil {
		fmt.Fprintln(ch.Stderr(), "tulli: unsupported command (this is a read-only git proxy)")
		exit(ch, 1)
		return
	}

	adm, err := s.gate.Admit(ctx, ref, verb, id)
	if err != nil {
		s.log.Error("admit failed", "ref", ref.String(), "verb", verb, "err", err)
		fmt.Fprintln(ch.Stderr(), "tulli: upstream mirror unavailable")
		exit(ch, 128)
		return
	}
	if !adm.Allowed {
		// git prefixes remote stderr lines with "remote: " on the client side, so
		// the operator message is written raw here (spec §3.3).
		fmt.Fprintln(ch.Stderr(), adm.BlockMsg)
		exit(ch, 1)
		return
	}

	s.log.Info("serve", "ref", ref.String(), "verb", verb, "src", srcIP, "user", id.Login)
	cmd := exec.CommandContext(ctx, "git", "upload-pack", adm.RepoPath)
	if gitProtocol != "" {
		cmd.Env = append(os.Environ(), "GIT_PROTOCOL="+gitProtocol)
	}
	cw := &countWriter{w: ch}
	cmd.Stdin = ch
	cmd.Stdout = cw
	cmd.Stderr = ch.Stderr()
	code := exitCode(cmd.Run())
	exit(ch, code)

	s.gate.FinishAudit(ctx, core.Access{RepoID: adm.RepoID, UserID: adm.UserID, SourceIP: srcIP, Status: 200, Bytes: cw.n})
}

// countWriter counts the bytes streamed to the client for the audit trail.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

// exit sends the SSH exit-status so git sees the command's result.
func exit(ch ssh.Channel, code int) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
}

func reply(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 128
}

func remoteIP(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
