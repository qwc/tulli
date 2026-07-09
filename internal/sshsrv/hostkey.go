package sshsrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey returns the SSH host key at path, generating and
// persisting a fresh ed25519 key (0600) on first run so the server identity is
// stable across restarts — clients don't get known-hosts churn.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return ssh.ParsePrivateKey(data)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "tulli host key")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromSigner(priv)
}
