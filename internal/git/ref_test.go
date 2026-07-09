package git

import "testing"

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantHost string
		wantPath string
		wantVerb string
		wantErr  bool
	}{
		{"info/refs", "/repos/github.com/octocat/Hello-World/info/refs", "github.com", "octocat/Hello-World", VerbInfoRefs, false},
		{"upload-pack", "/repos/github.com/octocat/Hello-World/git-upload-pack", "github.com", "octocat/Hello-World", VerbUploadPack, false},
		{"receive-pack recognised", "/repos/github.com/o/r/git-receive-pack", "github.com", "o/r", VerbReceivePack, false},
		{"deep path (subgroups)", "/repos/gitlab.com/grp/sub/proj/info/refs", "gitlab.com", "grp/sub/proj", VerbInfoRefs, false},
		{"traversal rejected", "/repos/example.com/../etc/info/refs", "", "", "", true},
		{"dot segment rejected", "/repos/example.com/./x/info/refs", "", "", "", true},
		{"host only (too short)", "/repos/github.com/info/refs", "", "", "", true},
		{"not a repos path", "/healthz", "", "", "", true},
		{"unsupported endpoint", "/repos/github.com/o/r/objects/info/packs", "", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, verb, err := ParseRequest(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ref=%v verb=%q", ref, verb)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref.Host != tc.wantHost || ref.Path != tc.wantPath || verb != tc.wantVerb {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", ref.Host, ref.Path, verb, tc.wantHost, tc.wantPath, tc.wantVerb)
			}
		})
	}
}

func TestParseSSHCommand(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		wantHost string
		wantPath string
		wantVerb string
		wantErr  bool
	}{
		{"upload-pack quoted", "git-upload-pack '/github.com/octocat/Hello-World'", "github.com", "octocat/Hello-World", VerbUploadPack, false},
		{"upload-pack unquoted", "git-upload-pack /github.com/o/r", "github.com", "o/r", VerbUploadPack, false},
		{"strips .git suffix", "git-upload-pack '/github.com/o/r.git'", "github.com", "o/r", VerbUploadPack, false},
		{"no leading slash", "git-upload-pack 'github.com/o/r'", "github.com", "o/r", VerbUploadPack, false},
		{"subgroups", "git-upload-pack '/gitlab.com/grp/sub/proj'", "gitlab.com", "grp/sub/proj", VerbUploadPack, false},
		{"receive-pack recognised", "git-receive-pack '/github.com/o/r'", "github.com", "o/r", VerbReceivePack, false},
		{"traversal rejected", "git-upload-pack '/example.com/../etc'", "", "", "", true},
		{"host only (too short)", "git-upload-pack '/github.com'", "", "", "", true},
		{"interactive shell rejected", "bash -i", "", "", "", true},
		{"bare command no arg", "git-upload-pack", "", "", "", true},
		{"empty", "", "", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, verb, err := ParseSSHCommand(tc.cmd)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ref=%v verb=%q", ref, verb)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref.Host != tc.wantHost || ref.Path != tc.wantPath || verb != tc.wantVerb {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", ref.Host, ref.Path, verb, tc.wantHost, tc.wantPath, tc.wantVerb)
			}
		})
	}
}

func TestUpstreamURL(t *testing.T) {
	r := RepoRef{Host: "github.com", Path: "octocat/Hello-World"}
	tests := []struct{ base, want string }{
		{"", "https://github.com/octocat/Hello-World"},
		{"https://", "https://github.com/octocat/Hello-World"},
		{"file:///tmp/up", "file:///tmp/up/github.com/octocat/Hello-World"},
		{"file:///tmp/up/", "file:///tmp/up/github.com/octocat/Hello-World"},
	}
	for _, tc := range tests {
		if got := r.UpstreamURL(tc.base); got != tc.want {
			t.Errorf("UpstreamURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

func TestMirrorDir(t *testing.T) {
	r := RepoRef{Host: "github.com", Path: "octocat/Hello-World"}
	want := "/data/mirrors/github.com/octocat/Hello-World.git"
	if got := r.MirrorDir("/data/mirrors"); got != want {
		t.Errorf("MirrorDir = %q, want %q", got, want)
	}
}
