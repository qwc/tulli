// Package git owns everything that talks to the on-disk bare mirrors and the
// real `git` binary: path resolution, the lazy mirror, and the http-backend
// handoff. It is deliberately transport-agnostic — the HTTP/SSH adapters call
// into it via the core hallway (see internal/core).
package git

import (
	"errors"
	"path/filepath"
	"strings"
)

// Git smart-HTTP verbs we route. tulli is read-only, so git-receive-pack is
// recognised only to be refused.
const (
	VerbInfoRefs    = "info/refs"
	VerbUploadPack  = "git-upload-pack"
	VerbReceivePack = "git-receive-pack"
)

var (
	ErrNotRepoPath = errors.New("not a /repos/ path")
	ErrUnsupported = errors.New("unsupported git endpoint")
	ErrBadRepo     = errors.New("malformed repo path")
)

// RepoRef is the upstream identity parsed from the URL. The URL is dumb and
// total (spec §thesis 3): /repos/<host>/<path...> maps 1:1 to the upstream and,
// separately, to the on-disk mirror. Nothing is aliased or shortened.
type RepoRef struct {
	Host string // e.g. github.com
	Path string // e.g. owner/repo (may contain further slashes, e.g. gitlab subgroups)
}

func (r RepoRef) String() string { return r.Host + "/" + r.Path }

// MirrorDir is the bare-mirror path on disk: <root>/<host>/<path>.git
func (r RepoRef) MirrorDir(root string) string {
	return filepath.Join(root, r.Host, filepath.FromSlash(r.Path)) + ".git"
}

// UpstreamURL is where we clone/fetch from. base defaults to "https://" (public
// FOSS, anonymous — spec §2.1). A base ending in "://" is treated as a bare
// scheme (https:// -> https://host/path); any other base is a URL prefix, which
// is how local file:// fixtures are wired for tests
// (file:///tmp/up -> file:///tmp/up/host/path).
func (r RepoRef) UpstreamURL(base string) string {
	if base == "" {
		base = "https://"
	}
	if strings.HasSuffix(base, "://") {
		return base + r.Host + "/" + r.Path
	}
	return strings.TrimRight(base, "/") + "/" + r.Host + "/" + r.Path
}

// ParseRequest splits a request path like
//
//	/repos/github.com/owner/repo/info/refs
//	/repos/github.com/owner/repo/git-upload-pack
//
// into the RepoRef and the git verb. It rejects path traversal and malformed
// inputs. The dumb-HTTP endpoints (HEAD, objects/…) are not supported — tulli is
// smart-protocol only.
func ParseRequest(urlPath string) (ref RepoRef, verb string, err error) {
	rest, ok := strings.CutPrefix(urlPath, "/repos/")
	if !ok {
		return ref, "", ErrNotRepoPath
	}

	var repoPart string
	switch {
	case strings.HasSuffix(rest, "/"+VerbInfoRefs):
		verb, repoPart = VerbInfoRefs, strings.TrimSuffix(rest, "/"+VerbInfoRefs)
	case strings.HasSuffix(rest, "/"+VerbUploadPack):
		verb, repoPart = VerbUploadPack, strings.TrimSuffix(rest, "/"+VerbUploadPack)
	case strings.HasSuffix(rest, "/"+VerbReceivePack):
		verb, repoPart = VerbReceivePack, strings.TrimSuffix(rest, "/"+VerbReceivePack)
	default:
		return ref, "", ErrUnsupported
	}

	segs := strings.Split(repoPart, "/")
	if len(segs) < 2 { // need at least host + one path segment
		return ref, "", ErrBadRepo
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return ref, "", ErrBadRepo
		}
	}
	ref.Host = segs[0]
	ref.Path = strings.Join(segs[1:], "/")
	return ref, verb, nil
}
