// Package checker holds the AWS-independent core: the certificate model,
// the evaluation rules, and the reporting/exit-code logic. It talks to AWS
// only through the Lister interface, so tests drive it with a fake.
package checker

import (
	"context"
	"sort"
	"time"
)

// Certificate is the raw, provider-neutral view of an ACM certificate that the
// evaluator needs. The AWS adapter fills these in; the fake in tests fabricates
// them directly.
type Certificate struct {
	ARN      string
	Domain   string
	Region   string
	NotAfter *time.Time
	// Type is "AMAZON_ISSUED" or "IMPORTED".
	Type string
	// RenewalEligibility is "ELIGIBLE" or "INELIGIBLE".
	RenewalEligibility string
	// Status is the ACM status, e.g. "ISSUED".
	Status  string
	InUseBy []string
}

// Lister returns every certificate in a single region. The adapter implements
// it against the ACM API; the fake returns canned data.
type Lister interface {
	List(ctx context.Context, region string) ([]Certificate, error)
}

// Result is one evaluated certificate, ready to render or serialize.
type Result struct {
	ARN          string `json:"arn"`
	Domain       string `json:"domain"`
	Region       string `json:"region"`
	NotAfter     string `json:"not_after"`
	DaysLeft     *int   `json:"days_left"`
	Renewable    bool   `json:"renewable"`
	InUse        bool   `json:"in_use"`
	Reason       string `json:"reason"`
	notAfterTime *time.Time
	expiring     bool
	certType     string
}

// Expiring reports whether the certificate is inside the danger window.
func (r Result) Expiring() bool { return r.expiring }

// Options tune the evaluation.
type Options struct {
	// Days is the expiry threshold; a cert is "expiring" when it lapses within
	// this many days.
	Days int
	// Now is injectable for deterministic tests. Zero means time.Now().
	Now time.Time
}

// Evaluate turns raw certificates into sorted results (soonest expiry first).
func Evaluate(certs []Certificate, opt Options) []Result {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	out := make([]Result, 0, len(certs))
	for _, c := range certs {
		out = append(out, evaluate(c, now, opt.Days))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return lessByExpiry(out[i], out[j])
	})
	return out
}

// lessByExpiry orders soonest-expiring first; certs with no NotAfter sort last.
func lessByExpiry(a, b Result) bool {
	switch {
	case a.notAfterTime == nil && b.notAfterTime == nil:
		return a.Domain < b.Domain
	case a.notAfterTime == nil:
		return false
	case b.notAfterTime == nil:
		return true
	default:
		return a.notAfterTime.Before(*b.notAfterTime)
	}
}

func evaluate(c Certificate, now time.Time, days int) Result {
	r := Result{
		ARN:          c.ARN,
		Domain:       c.Domain,
		Region:       c.Region,
		InUse:        len(c.InUseBy) > 0,
		notAfterTime: c.NotAfter,
		certType:     c.Type,
	}

	if c.NotAfter != nil {
		r.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
		d := daysUntil(now, *c.NotAfter)
		r.DaysLeft = &d
		r.expiring = d <= days
	}

	// ACM only auto-renews Amazon-issued certs that are eligible and actually
	// attached to something. Anything else is a manual-renewal landmine.
	r.Renewable = c.Type == "AMAZON_ISSUED" &&
		c.RenewalEligibility == "ELIGIBLE" &&
		len(c.InUseBy) > 0

	r.Reason = reason(c, r)
	return r
}

// reason produces a short human explanation, leading with expiry when relevant.
func reason(c Certificate, r Result) string {
	var parts []string
	if r.expiring && r.DaysLeft != nil {
		switch {
		case *r.DaysLeft < 0:
			parts = append(parts, "already expired")
		case *r.DaysLeft == 0:
			parts = append(parts, "expires today")
		default:
			parts = append(parts, "expires soon")
		}
	}
	if !r.Renewable {
		switch {
		case c.Type == "IMPORTED":
			parts = append(parts, "imported (no auto-renew)")
		case c.RenewalEligibility != "ELIGIBLE":
			parts = append(parts, "renewal ineligible")
		case len(c.InUseBy) == 0:
			parts = append(parts, "not in use")
		default:
			parts = append(parts, "not renewable")
		}
	}
	if len(parts) == 0 {
		return "ok"
	}
	return joinReasons(parts)
}

func joinReasons(parts []string) string {
	out := parts[0]
	for _, p := range parts[1:] {
		out += "; " + p
	}
	return out
}

// daysUntil returns whole days from now to t, rounded toward zero at the day
// boundary (a cert expiring in 23h reports 0 days left, i.e. "today").
func daysUntil(now, t time.Time) int {
	return int(t.Sub(now).Hours() / 24)
}

// FailMode controls which conditions turn the exit code red.
type FailMode string

const (
	FailNone         FailMode = "none"
	FailExpiring     FailMode = "expiring"
	FailNonRenewable FailMode = "non-renewable"
)

// AtRisk reports whether a single result should trip the given fail mode.
func AtRisk(r Result, mode FailMode) bool {
	switch mode {
	case FailNone:
		return false
	case FailExpiring:
		return r.expiring
	case FailNonRenewable:
		return r.expiring || !r.Renewable
	default:
		return r.expiring
	}
}

// ExitCode returns 1 if any result is at risk under the fail mode, else 0.
func ExitCode(results []Result, mode FailMode) int {
	for _, r := range results {
		if AtRisk(r, mode) {
			return 1
		}
	}
	return 0
}
