package verdict

import (
	"context"
	"testing"
)

func TestResolve(t *testing.T) {
	high := Finding{Scanner: "gitleaks", Severity: SeverityHigh, Fingerprint: "fp1"}
	high2 := Finding{Scanner: "gitleaks", Severity: SeverityHigh, Fingerprint: "fp2"}
	low := Finding{Scanner: "gitleaks", Severity: SeverityLow, Fingerprint: "fp3"}

	tests := []struct {
		name       string
		findings   []Finding
		overridden map[string]bool
		want       string
	}{
		{"no findings", nil, nil, DecisionClean},
		{"only low", []Finding{low}, nil, DecisionClean},
		{"one high", []Finding{high}, nil, DecisionQuarantined},
		{"high overridden", []Finding{high}, map[string]bool{"fp1": true}, DecisionClean},
		{"two high one overridden", []Finding{high, high2}, map[string]bool{"fp1": true}, DecisionQuarantined},
		{"two high both overridden", []Finding{high, high2}, map[string]bool{"fp1": true, "fp2": true}, DecisionClean},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := Resolve(tt.findings, tt.overridden)
			if got != tt.want {
				t.Errorf("decision = %q, want %q", got, tt.want)
			}
			if got == DecisionQuarantined && reason == "" {
				t.Error("a block must carry a reason")
			}
		})
	}
}

func TestResolveReason(t *testing.T) {
	if _, r := Resolve([]Finding{{Severity: SeverityHigh, Scanner: "gitleaks"}}, nil); r != "1 HIGH secret (gitleaks)" {
		t.Errorf("reason = %q", r)
	}
	two := []Finding{{Severity: SeverityHigh, Scanner: "gitleaks"}, {Severity: SeverityHigh, Scanner: "gitleaks"}}
	if _, r := Resolve(two, nil); r != "2 HIGH secrets (gitleaks)" {
		t.Errorf("reason = %q", r)
	}
}

// fakeStore is an in-memory verdict.Store for the recompute tests.
type fakeStore struct {
	findings   map[string][]Finding // ref -> findings
	overridden map[string][]string  // ref -> fingerprints
	written    []written
}
type written struct {
	ref, decision, reason string
}

func (f *fakeStore) FindingsForRef(_ context.Context, _ int64, ref string) ([]Finding, error) {
	return f.findings[ref], nil
}
func (f *fakeStore) OverriddenFingerprints(_ context.Context, _ int64, ref string) ([]string, error) {
	return f.overridden[ref], nil
}
func (f *fakeStore) AffectedRefs(_ context.Context, _ int64) ([]string, error) {
	refs := make([]string, 0, len(f.findings))
	for r := range f.findings {
		refs = append(refs, r)
	}
	return refs, nil
}
func (f *fakeStore) InsertVerdict(_ context.Context, _ int64, ref, decision, reason string) error {
	f.written = append(f.written, written{ref, decision, reason})
	return nil
}
func (f *fakeStore) CurrentDecision(_ context.Context, _ int64, ref string) (string, error) {
	for i := len(f.written) - 1; i >= 0; i-- {
		if f.written[i].ref == ref {
			return f.written[i].decision, nil
		}
	}
	return "", nil
}

func TestRecomputeRef_QuarantineThenOverrideClears(t *testing.T) {
	fs := &fakeStore{
		findings: map[string][]Finding{
			"refs/tags/evil": {{Severity: SeverityHigh, Scanner: "gitleaks", Fingerprint: "fp1"}},
		},
		overridden: map[string][]string{},
	}
	ctx := context.Background()

	// First pass: HIGH secret, no override → QUARANTINED.
	if d, err := RecomputeRef(ctx, fs, 1, "refs/tags/evil"); err != nil || d != DecisionQuarantined {
		t.Fatalf("decision = %q err %v, want QUARANTINED", d, err)
	}

	// Override the fingerprint → recompute → CLEAN (spec §12 step 4).
	fs.overridden["refs/tags/evil"] = []string{"fp1"}
	if d, err := RecomputeRef(ctx, fs, 1, "refs/tags/evil"); err != nil || d != DecisionClean {
		t.Fatalf("after override decision = %q err %v, want CLEAN", d, err)
	}
}

func TestRecomputeRepo_CleanBaselineWhenNoFindings(t *testing.T) {
	fs := &fakeStore{findings: map[string][]Finding{}}
	if err := RecomputeRepo(context.Background(), fs, 1); err != nil {
		t.Fatal(err)
	}
	if len(fs.written) != 1 || fs.written[0].ref != "" || fs.written[0].decision != DecisionClean {
		t.Fatalf("want one repo-wide CLEAN verdict, got %+v", fs.written)
	}
}
