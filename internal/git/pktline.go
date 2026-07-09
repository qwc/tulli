package git

import (
	"fmt"
	"io"
	"net/http"
)

// pktLine encodes s as a single git pkt-line: a 4-hex-digit length prefix (which
// counts itself) followed by the payload. Callers keep payloads well under the
// 65516-byte pkt-line limit, so no chunking is needed.
func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// WriteBlock aborts a smart-HTTP fetch with an operator message. git renders it
// as `fatal: remote error: <msg>` and exits non-zero. Per spec §3.3 the response
// carries the upload-pack advertisement content-type and a single ERR pkt-line,
// written *before* any handoff to git-http-backend.
//
// The status is 200, not 403: git's HTTP transport only reads (and surfaces) the
// ERR body on a 2xx response — on 4xx it prints a generic "returned error: 403"
// and drops our message. Returning 200 with an ERR pkt-line is the smart-protocol
// convention for application-level refusals (validated against real git). This is
// info/refs only, since that is where git reads the advertisement.
func WriteBlock(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, pktLine("ERR "+msg))
}
