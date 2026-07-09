package git

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestPktLine(t *testing.T) {
	// "hello\n" is 6 bytes; +4 for the length prefix = 10 = 0x000a.
	if got := pktLine("hello\n"); got != "000ahello\n" {
		t.Errorf("pktLine = %q, want %q", got, "000ahello\n")
	}
	if got := pktLine(""); got != "0004" {
		t.Errorf("empty pktLine = %q, want 0004", got)
	}
}

func TestWriteBlock(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteBlock(rr, "tulli: repo QUARANTINED — secret")

	// Status 200 is load-bearing: git only reads the ERR body on a 2xx response.
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("content-type = %q", ct)
	}
	body := rr.Body.String()
	if len(body) < 8 || body[4:8] != "ERR " {
		t.Fatalf("body = %q, want a length-prefixed ERR packet", body)
	}
	// The 4-hex length prefix must equal the whole packet length.
	var n int
	if _, err := fmt.Sscanf(body[:4], "%04x", &n); err != nil || n != len(body) {
		t.Errorf("length prefix %q != packet length %d", body[:4], len(body))
	}
}
