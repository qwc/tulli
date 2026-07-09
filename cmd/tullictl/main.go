// Command tullictl is a thin client for the tulli web API (stage 6b) — the
// kubectl→apiserver shape: it never touches the database or the mirrors, it just
// calls the API with a bearer token. Configure it with:
//
//	TULLI_URL     base URL of the web API (e.g. http://localhost:8081)
//	TULLI_TOKEN   bearer token (a user token, or the bootstrap admin token)
//
// Usage:
//
//	tullictl repos
//	tullictl repo <id>
//	tullictl block   <repoID> <ref|-> <reason...>     (- = repo-wide)
//	tullictl unblock <repoID> <ref|-> <reason...>
//	tullictl override <repoID> <ref|-> <fingerprint> <reason...>
//	tullictl user-create  <name> <role> <kind>
//	tullictl token-create <userID>
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	base := strings.TrimRight(os.Getenv("TULLI_URL"), "/")
	if base == "" {
		base = "http://localhost:8081"
	}
	c := &client{base: base, token: os.Getenv("TULLI_TOKEN")}

	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "repos":
		err = c.get("/api/repos")
	case "repo":
		err = needN(args, 1, "repo <id>", func() error { return c.get("/api/repos/" + args[0]) })
	case "block":
		err = blockCmd(c, args, "block")
	case "unblock":
		err = blockCmd(c, args, "unblock")
	case "override":
		err = overrideCmd(c, args)
	case "user-create":
		err = needN(args, 3, "user-create <name> <role> <kind>", func() error {
			return c.post("/api/users", map[string]any{"name": args[0], "role": args[1], "kind": args[2]})
		})
	case "token-create":
		err = needN(args, 1, "token-create <userID>", func() error {
			return c.post("/api/users/"+args[0]+"/tokens", nil)
		})
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tullictl:", err)
		os.Exit(1)
	}
}

// blockCmd handles both block and unblock: <repoID> <ref|-> <reason...>.
func blockCmd(c *client, args []string, verb string) error {
	if len(args) < 3 {
		return fmt.Errorf("%s <repoID> <ref|-> <reason...>", verb)
	}
	return c.post(fmt.Sprintf("/api/repos/%s/%s", args[0], verb), map[string]any{
		"ref":    refArg(args[1]),
		"reason": strings.Join(args[2:], " "),
	})
}

func overrideCmd(c *client, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("override <repoID> <ref|-> <fingerprint> <reason...>")
	}
	return c.post(fmt.Sprintf("/api/repos/%s/overrides", args[0]), map[string]any{
		"ref":         refArg(args[1]),
		"fingerprint": args[2],
		"reason":      strings.Join(args[3:], " "),
	})
}

// refArg maps the "-" sentinel to "" (repo-wide).
func refArg(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func needN(args []string, n int, usageLine string, fn func() error) error {
	if len(args) < n {
		return fmt.Errorf("usage: %s", usageLine)
	}
	return fn()
}

type client struct {
	base  string
	token string
}

func (c *client) get(path string) error { return c.do(http.MethodGet, path, nil) }
func (c *client) post(path string, body any) error {
	return c.do(http.MethodPost, path, body)
}

func (c *client) do(method, path string, body any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, buf)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	fmt.Println(pretty(raw))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	return nil
}

// pretty re-indents a JSON response for the terminal, or returns it verbatim.
func pretty(raw []byte) string {
	var out bytes.Buffer
	if json.Indent(&out, raw, "", "  ") == nil {
		return out.String()
	}
	return string(raw)
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
tullictl — client for the tulli web API (set TULLI_URL, TULLI_TOKEN)

  repos
  repo          <id>
  block         <repoID> <ref|-> <reason...>     (- = repo-wide)
  unblock       <repoID> <ref|-> <reason...>
  override      <repoID> <ref|-> <fingerprint> <reason...>
  user-create   <name> <role> <kind>
  token-create  <userID>`))
}
