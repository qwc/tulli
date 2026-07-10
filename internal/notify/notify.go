// Package notify is tulli's notification seam (spec §6d): when a repo/ref is
// quarantined, the people who pulled it are told. The Notifier interface is the
// delivery seam — the prototype ships a LogNotifier (logs the notice), and SMTP
// or webhook sinks drop in behind the same interface later. The reconciler
// decides *when* to notify (once per verdict, idempotent); this package only
// says *how* a notice is delivered.
package notify

import (
	"context"
	"log/slog"
	"strings"

	"codeberg.org/qwc/tulli/internal/core"
)

// Notice is one quarantine notification. Recipients are resolved from the audit
// trail (who pulled the repo). Ref is "" for a repo-wide block; Refs lists the
// hidden refs for a ref-level block. The notice is repo-precise, not ref-precise,
// about *who* pulled (we know the repo, not the ref they fetched — §6d).
type Notice struct {
	RepoID     int64
	Repo       string // mirror path (display)
	RepoWide   bool
	Refs       []string
	Reason     string
	Recipients []core.Recipient
}

// Notifier delivers a Notice. Implementations must be safe for concurrent use.
type Notifier interface {
	Deliver(ctx context.Context, n Notice) error
}

// LogNotifier is the prototype sink: it logs the notice at WARN. The
// notifications table row is recorded by the reconciler (idempotency); this is
// the human-visible delivery.
type LogNotifier struct{ log *slog.Logger }

func NewLogNotifier(log *slog.Logger) *LogNotifier { return &LogNotifier{log: log} }

func (n *LogNotifier) Deliver(_ context.Context, notice Notice) error {
	logins := make([]string, 0, len(notice.Recipients))
	for _, r := range notice.Recipients {
		logins = append(logins, r.Login)
	}
	scope := "repo-wide"
	if !notice.RepoWide {
		scope = strings.Join(notice.Refs, ",")
	}
	n.log.Warn("QUARANTINE NOTICE",
		"repo", notice.Repo,
		"scope", scope,
		"reason", notice.Reason,
		"recipients", strings.Join(logins, ","),
		"recipient_count", len(logins),
	)
	return nil
}

// PayloadDescriptor is a short, stable descriptor stored in notifications.
// payload_path — a real payload file/URL is a later refinement.
func PayloadDescriptor(n Notice) string {
	if n.RepoWide {
		return "log:quarantine/" + n.Repo + "/(repo-wide)"
	}
	return "log:quarantine/" + n.Repo + "/" + strings.Join(n.Refs, ",")
}
