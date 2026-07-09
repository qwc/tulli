// Package verdict holds the blocking-set rule (spec §6.7/§11.4) and the recompute
// that turns raw findings + overrides into a per-(repo,ref) decision. The rule is
// pure; Recompute wires it to the store. This is the single source of the
// enforcement logic — the scan worker and (later) the web API both call it, so
// there is one place the rules live regardless of who writes the DB.
package verdict

import "context"

// Decisions written to the verdicts table (spec §9 CHECK).
const (
	DecisionClean       = "CLEAN"
	DecisionQuarantined = "QUARANTINED"
	DecisionOverridden  = "OVERRIDDEN"
)

// Severity levels (spec §9 CHECK). Only HIGH actuates an auto-quarantine (§6.6).
const (
	SeverityLow    = "LOW"
	SeverityMedium = "MEDIUM"
	SeverityHigh   = "HIGH"
)

// Finding is one scanner hit, attributed to a commit and (post-attribution) a ref.
type Finding struct {
	Scanner     string
	Severity    string
	RuleID      string
	FilePath    string
	Line        int
	Commit      string
	Fingerprint string
	Description string
}

// Resolve applies the blocking set (spec §6.7): a ref is QUARANTINED iff some
// HIGH finding on it is still applicable AND not waived by an override; otherwise
// CLEAN. Overrides are keyed by the stable gitleaks Fingerprint (§8.1). Returns
// the decision and a short human reason for the block message.
func Resolve(findings []Finding, overridden map[string]bool) (decision, reason string) {
	blocking := 0
	for _, f := range findings {
		if f.Severity != SeverityHigh {
			continue // only HIGH secrets auto-block (§6.6); lower severities inform, not gate
		}
		if overridden[f.Fingerprint] {
			continue // waived by an override (VEX, §8.6)
		}
		blocking++
	}
	if blocking == 0 {
		return DecisionClean, ""
	}
	return DecisionQuarantined, secretsReason(blocking, findings)
}

func secretsReason(n int, findings []Finding) string {
	scanner := "scanner"
	for _, f := range findings {
		if f.Scanner != "" {
			scanner = f.Scanner
			break
		}
	}
	return plural(n, "HIGH secret") + " (" + scanner + ")"
}

func plural(n int, unit string) string {
	s := itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Store is the narrow persistence seam Recompute needs. Both internal/store.Mem
// and internal/store/pg satisfy it. Findings/overrides are pre-attributed to the
// ref (migration 00002), so these are plain reads.
type Store interface {
	FindingsForRef(ctx context.Context, repoID int64, ref string) ([]Finding, error)
	OverriddenFingerprints(ctx context.Context, repoID int64, ref string) ([]string, error)
	AffectedRefs(ctx context.Context, repoID int64) ([]string, error)
	CurrentDecision(ctx context.Context, repoID int64, ref string) (string, error)
	InsertVerdict(ctx context.Context, repoID int64, ref, decision, reason string) error
}

// RecomputeRef re-derives the current verdict for one (repo, ref) from its stored
// findings and overrides, and writes it **only if it changed** — so it is safe to
// call repeatedly from the scan worker and the periodic reconcile sweep without
// growing the append-only verdicts table. Returns the current decision.
func RecomputeRef(ctx context.Context, s Store, repoID int64, ref string) (string, error) {
	findings, err := s.FindingsForRef(ctx, repoID, ref)
	if err != nil {
		return "", err
	}
	ov, err := s.OverriddenFingerprints(ctx, repoID, ref)
	if err != nil {
		return "", err
	}
	set := make(map[string]bool, len(ov))
	for _, fp := range ov {
		set[fp] = true
	}
	decision, reason := Resolve(findings, set)
	return decision, writeIfChanged(ctx, s, repoID, ref, decision, reason)
}

// RecomputeRepo recomputes every ref that has findings for the repo (the demand
// set the scan produced). A repo with no findings gets a repo-wide CLEAN baseline
// so a scanned-clean repo reads as CLEAN (spec §12 step 1).
func RecomputeRepo(ctx context.Context, s Store, repoID int64) error {
	refs, err := s.AffectedRefs(ctx, repoID)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return writeIfChanged(ctx, s, repoID, "", DecisionClean, "")
	}
	for _, ref := range refs {
		if _, err := RecomputeRef(ctx, s, repoID, ref); err != nil {
			return err
		}
	}
	return nil
}

// writeIfChanged inserts a verdict row only when the decision differs from the
// current one, keeping the periodic sweep from bloating the verdicts table.
func writeIfChanged(ctx context.Context, s Store, repoID int64, ref, decision, reason string) error {
	cur, err := s.CurrentDecision(ctx, repoID, ref)
	if err != nil {
		return err
	}
	if cur == decision {
		return nil
	}
	return s.InsertVerdict(ctx, repoID, ref, decision, reason)
}
