package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fakeLister returns canned certificates per region, no AWS involved.
type fakeLister struct {
	byRegion map[string][]Certificate
}

func (f fakeLister) List(_ context.Context, region string) ([]Certificate, error) {
	return f.byRegion[region], nil
}

func at(d time.Time) *time.Time { return &d }

func fixtures(now time.Time) []Certificate {
	return []Certificate{
		{ // healthy: amazon-issued, eligible, in use, far from expiry
			ARN: "arn:healthy", Domain: "healthy.example.com", Region: "us-east-1",
			NotAfter: at(now.Add(200 * 24 * time.Hour)),
			Type:     "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE",
			Status: "ISSUED", InUseBy: []string{"arn:elb/app"},
		},
		{ // expiring: amazon-issued but only 10 days left
			ARN: "arn:expiring", Domain: "expiring.example.com", Region: "us-east-1",
			NotAfter: at(now.Add(10 * 24 * time.Hour)),
			Type:     "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE",
			Status: "ISSUED", InUseBy: []string{"arn:cloudfront/dist"},
		},
		{ // imported: never auto-renews, and expiring
			ARN: "arn:imported", Domain: "imported.example.com", Region: "eu-west-1",
			NotAfter: at(now.Add(5 * 24 * time.Hour)),
			Type:     "IMPORTED", RenewalEligibility: "INELIGIBLE",
			Status: "ISSUED", InUseBy: []string{"arn:elb/legacy"},
		},
		{ // not in use: amazon-issued, eligible, but attached to nothing
			ARN: "arn:unused", Domain: "unused.example.com", Region: "eu-west-1",
			NotAfter: at(now.Add(300 * 24 * time.Hour)),
			Type:     "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE",
			Status: "ISSUED", InUseBy: nil,
		},
	}
}

func collect(t *testing.T, now time.Time, regions ...string) []Result {
	t.Helper()
	f := fakeLister{byRegion: map[string][]Certificate{
		"us-east-1": fixtures(now)[:2],
		"eu-west-1": fixtures(now)[2:],
	}}
	var all []Certificate
	for _, r := range regions {
		certs, err := f.List(context.Background(), r)
		if err != nil {
			t.Fatalf("List(%s): %v", r, err)
		}
		all = append(all, certs...)
	}
	return Evaluate(all, Options{Days: 30, Now: now})
}

func find(results []Result, domain string) (Result, bool) {
	for _, r := range results {
		if r.Domain == domain {
			return r, true
		}
	}
	return Result{}, false
}

func TestEvaluateFlagsAndReasons(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	results := collect(t, now, "us-east-1", "eu-west-1")

	cases := []struct {
		domain    string
		expiring  bool
		renewable bool
		inUse     bool
		reasonSub string
	}{
		{"healthy.example.com", false, true, true, "ok"},
		{"expiring.example.com", true, true, true, "expires soon"},
		{"imported.example.com", true, false, true, "imported"},
		{"unused.example.com", false, false, false, "not in use"},
	}
	for _, c := range cases {
		r, ok := find(results, c.domain)
		if !ok {
			t.Fatalf("missing result for %s", c.domain)
		}
		if r.Expiring() != c.expiring {
			t.Errorf("%s expiring=%v want %v", c.domain, r.Expiring(), c.expiring)
		}
		if r.Renewable != c.renewable {
			t.Errorf("%s renewable=%v want %v", c.domain, r.Renewable, c.renewable)
		}
		if r.InUse != c.inUse {
			t.Errorf("%s inUse=%v want %v", c.domain, r.InUse, c.inUse)
		}
		if !strings.Contains(r.Reason, c.reasonSub) {
			t.Errorf("%s reason=%q want substring %q", c.domain, r.Reason, c.reasonSub)
		}
	}
}

func TestSortedBySoonestExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	results := collect(t, now, "us-east-1", "eu-west-1")
	// imported (5d) < expiring (10d) < healthy (200d) < unused (300d)
	want := []string{
		"imported.example.com",
		"expiring.example.com",
		"healthy.example.com",
		"unused.example.com",
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results want %d", len(results), len(want))
	}
	for i, d := range want {
		if results[i].Domain != d {
			t.Errorf("position %d = %s want %s", i, results[i].Domain, d)
		}
	}
}

func TestExitCodeExpiring(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// Only the healthy region: nothing inside 30 days.
	f := fakeLister{byRegion: map[string][]Certificate{
		"safe": {fixtures(now)[0]},
	}}
	safe, _ := f.List(context.Background(), "safe")
	if got := ExitCode(Evaluate(safe, Options{Days: 30, Now: now}), FailExpiring); got != 0 {
		t.Errorf("safe set exit=%d want 0", got)
	}

	risky := collect(t, now, "us-east-1")
	if got := ExitCode(risky, FailExpiring); got != 1 {
		t.Errorf("risky set exit=%d want 1", got)
	}
	if got := ExitCode(risky, FailNone); got != 0 {
		t.Errorf("fail-on none exit=%d want 0", got)
	}
}

func TestExitCodeNonRenewable(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// eu-west-1 has imported (expiring, non-renewable) and unused (non-renewable,
	// not expiring). Under fail-on expiring only imported trips; under
	// non-renewable both would, so exit is 1 either way here — assert the
	// distinction with a set that is only non-renewable, not expiring.
	f := fakeLister{byRegion: map[string][]Certificate{
		"eu-west-1": {fixtures(now)[3]}, // unused only
	}}
	unused, _ := f.List(context.Background(), "eu-west-1")
	results := Evaluate(unused, Options{Days: 30, Now: now})
	if got := ExitCode(results, FailExpiring); got != 0 {
		t.Errorf("unused fail-on expiring exit=%d want 0", got)
	}
	if got := ExitCode(results, FailNonRenewable); got != 1 {
		t.Errorf("unused fail-on non-renewable exit=%d want 1", got)
	}
}

func TestJSONShape(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	results := collect(t, now, "us-east-1")
	var buf bytes.Buffer
	if err := WriteJSON(&buf, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("empty JSON array")
	}
	for _, k := range []string{"arn", "domain", "region", "not_after", "days_left", "renewable", "in_use", "reason", "renewal_failing"} {
		if _, ok := decoded[0][k]; !ok {
			t.Errorf("JSON object missing key %q", k)
		}
	}
}

func TestNoNotAfterSortsLastAndNoDays(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	certs := []Certificate{
		{ARN: "a", Domain: "pending.example.com", Region: "us-east-1", Type: "AMAZON_ISSUED", RenewalEligibility: "INELIGIBLE", Status: "PENDING_VALIDATION"},
		{ARN: "b", Domain: "soon.example.com", Region: "us-east-1", NotAfter: at(now.Add(3 * 24 * time.Hour)), Type: "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE", InUseBy: []string{"x"}},
	}
	results := Evaluate(certs, Options{Days: 30, Now: now})
	if results[0].Domain != "soon.example.com" {
		t.Errorf("expected dated cert first, got %s", results[0].Domain)
	}
	last := results[len(results)-1]
	if last.DaysLeft != nil {
		t.Errorf("cert without NotAfter should have nil DaysLeft, got %v", *last.DaysLeft)
	}
	if last.NotAfter != "" {
		t.Errorf("cert without NotAfter should have empty NotAfter, got %q", last.NotAfter)
	}
}

// stuckRenewal is an eligible, in-use, far-from-expiry cert whose managed
// renewal is waiting on a validation that will not complete.
func stuckRenewal(now time.Time, status string) Certificate {
	return Certificate{
		ARN: "arn:stuck", Domain: "stuck.example.com", Region: "us-east-1",
		NotAfter: at(now.Add(50 * 24 * time.Hour)),
		Type:     "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE",
		Status: "ISSUED", InUseBy: []string{"arn:elb/app"},
		RenewalStatus: status,
		RenewalValidations: []DomainValidation{
			{Domain: "stuck.example.com", Status: "SUCCESS"},
			{Domain: "www.stuck.example.com", Status: "PENDING_VALIDATION"},
		},
	}
}

func TestRenewalStuck(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		status  string
		failing bool
		reason  string
	}{
		{"PENDING_VALIDATION", true, "renewal stuck: PENDING_VALIDATION (www.stuck.example.com PENDING_VALIDATION)"},
		{"FAILED", true, "renewal stuck: FAILED (www.stuck.example.com PENDING_VALIDATION)"},
		{"PENDING_AUTO_RENEWAL", false, "ok"},
		{"SUCCESS", false, "ok"},
		{"", false, "ok"},
	}
	for _, c := range cases {
		r := Evaluate([]Certificate{stuckRenewal(now, c.status)}, Options{Days: 30, Now: now})[0]
		if r.RenewalFailing != c.failing {
			t.Errorf("%q: RenewalFailing=%v want %v", c.status, r.RenewalFailing, c.failing)
		}
		if r.Reason != c.reason {
			t.Errorf("%q: reason=%q want %q", c.status, r.Reason, c.reason)
		}
		if r.RenewalStatus != c.status {
			t.Errorf("%q: RenewalStatus=%q", c.status, r.RenewalStatus)
		}
		if !r.Renewable {
			t.Errorf("%q: stuck renewal must not change Renewable", c.status)
		}
	}
}

func TestRenewalFailedReasonIncludesStatusReason(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := stuckRenewal(now, "FAILED")
	c.RenewalStatusReason = "CAA_ERROR"
	c.RenewalValidations = nil
	r := Evaluate([]Certificate{c}, Options{Days: 30, Now: now})[0]
	if want := "renewal stuck: FAILED (CAA_ERROR)"; r.Reason != want {
		t.Errorf("reason=%q want %q", r.Reason, want)
	}
}

func TestExitCodeRenewalFailing(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	stuck := Evaluate([]Certificate{stuckRenewal(now, "PENDING_VALIDATION")}, Options{Days: 30, Now: now})
	for mode, want := range map[FailMode]int{
		FailNone:           0,
		FailExpiring:       0,
		FailRenewalFailing: 1,
		FailNonRenewable:   1,
	} {
		if got := ExitCode(stuck, mode); got != want {
			t.Errorf("stuck renewal, fail-on %s: exit=%d want %d", mode, got, want)
		}
	}

	// renewal-failing still fails on expiring certs, but not on certs that are
	// merely non-renewable.
	if got := ExitCode(collect(t, now, "us-east-1"), FailRenewalFailing); got != 1 {
		t.Errorf("expiring set, fail-on renewal-failing: exit=%d want 1", got)
	}
	unused := Evaluate([]Certificate{fixtures(now)[3]}, Options{Days: 30, Now: now})
	if got := ExitCode(unused, FailRenewalFailing); got != 0 {
		t.Errorf("unused cert, fail-on renewal-failing: exit=%d want 0", got)
	}
}

func TestCNAMEProblemsInReasonAndFailing(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := fixtures(now)[0]
	c.CNAMEProblems = []CNAMEProblem{{Name: "_a.healthy.example.com", Kind: CNAMEMissing}}
	r := Evaluate([]Certificate{c}, Options{Days: 30, Now: now})[0]
	if !r.RenewalFailing {
		t.Error("missing CNAME should mark renewal failing")
	}
	if want := "validation CNAME missing: _a.healthy.example.com"; r.Reason != want {
		t.Errorf("reason=%q want %q", r.Reason, want)
	}

	c.CNAMEProblems = []CNAMEProblem{{Name: "_a.healthy.example.com", Kind: CNAMELookupFailed}}
	r = Evaluate([]Certificate{c}, Options{Days: 30, Now: now})[0]
	if r.RenewalFailing {
		t.Error("a failed lookup alone should not mark renewal failing")
	}
	if want := "validation CNAME lookup failed: _a.healthy.example.com"; r.Reason != want {
		t.Errorf("reason=%q want %q", r.Reason, want)
	}
}
