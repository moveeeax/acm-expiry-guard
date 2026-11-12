// Package checker holds the AWS-independent core: the certificate model,
// the evaluation rules, and the reporting/exit-code logic. It talks to AWS
// only through the Lister interface, so tests drive it with a fake.
package checker

import (
	"context"
	"sort"
	"strings"
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
	// RenewalStatus is RenewalSummary.RenewalStatus: "PENDING_AUTO_RENEWAL",
	// "PENDING_VALIDATION", "SUCCESS" or "FAILED". Empty when ACM has not
	// started a managed renewal for the certificate.
	RenewalStatus string
	// RenewalStatusReason is RenewalSummary.RenewalStatusReason, e.g. "CAA_ERROR".
	RenewalStatusReason string
	// RenewalValidations is the per-domain validation state of the managed
	// renewal (RenewalSummary.DomainValidationOptions).
	RenewalValidations []DomainValidation
	// ValidationRecords are the DNS validation CNAMEs ACM expects to exist.
	// CheckDNS resolves them.
	ValidationRecords []ValidationRecord
	// CNAMEProblems is filled by CheckDNS; nil when DNS was not checked.
	CNAMEProblems []CNAMEProblem
}

// DomainValidation is the validation state of one domain name.
type DomainValidation struct {
	Domain string
	// Status is "PENDING_VALIDATION", "SUCCESS" or "FAILED".
	Status string
}

// ValidationRecord is one DNS validation CNAME: Name must point to Value.
type ValidationRecord struct {
	Domain string
	Name   string
	Value  string
}

// Lister returns every certificate in a single region. The adapter implements
// it against the ACM API; the fake returns canned data.
type Lister interface {
	List(ctx context.Context, region string) ([]Certificate, error)
}

// Result is one evaluated certificate, ready to render or serialize.
type Result struct {
	ARN       string `json:"arn"`
	Domain    string `json:"domain"`
	Region    string `json:"region"`
	NotAfter  string `json:"not_after"`
	DaysLeft  *int   `json:"days_left"`
	Renewable bool   `json:"renewable"`
	InUse     bool   `json:"in_use"`
	Reason    string `json:"reason"`
	// RenewalStatus is ACM's managed renewal status, empty when no renewal
	// has started.
	RenewalStatus string `json:"renewal_status,omitempty"`
	// RenewalFailing is true when ACM's managed renewal is stuck or a DNS
	// validation CNAME is missing.
	RenewalFailing bool `json:"renewal_failing"`
	notAfterTime   *time.Time
	expiring       bool
	certType       string
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

	r.RenewalStatus = c.RenewalStatus
	r.RenewalFailing = renewalStuck(c) || len(brokenCNAMEs(c)) > 0

	r.Reason = reason(c, r)
	return r
}

// renewalStuck reports whether ACM's managed renewal needs a human: it is
// waiting on domain validation it cannot complete, or it has failed.
// PENDING_AUTO_RENEWAL is ACM still trying on its own and is not counted;
// if it drags on, the expiry threshold catches the certificate.
func renewalStuck(c Certificate) bool {
	return c.RenewalStatus == "PENDING_VALIDATION" || c.RenewalStatus == "FAILED"
}

// brokenCNAMEs returns the names of validation CNAMEs that are missing or point
// somewhere else. Lookup errors are not counted: they say nothing about the
// record itself.
func brokenCNAMEs(c Certificate) []string {
	var out []string
	for _, p := range c.CNAMEProblems {
		if p.Kind != CNAMELookupFailed {
			out = append(out, p.Name)
		}
	}
	return out
}

// renewalReasons explains a stuck renewal and any CNAME problems.
func renewalReasons(c Certificate) []string {
	var parts []string
	if renewalStuck(c) {
		s := "renewal stuck: " + c.RenewalStatus
		var details []string
		if c.RenewalStatusReason != "" {
			details = append(details, c.RenewalStatusReason)
		}
		for _, v := range c.RenewalValidations {
			if v.Status != "" && v.Status != "SUCCESS" {
				details = append(details, v.Domain+" "+v.Status)
			}
		}
		if len(details) > 0 {
			s += " (" + strings.Join(details, ", ") + ")"
		}
		parts = append(parts, s)
	}
	for _, p := range c.CNAMEProblems {
		parts = append(parts, "validation CNAME "+string(p.Kind)+": "+p.Name)
	}
	return parts
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
	parts = append(parts, renewalReasons(c)...)
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
	FailNone           FailMode = "none"
	FailExpiring       FailMode = "expiring"
	FailRenewalFailing FailMode = "renewal-failing"
	FailNonRenewable   FailMode = "non-renewable"
)

// AtRisk reports whether a single result should trip the given fail mode.
func AtRisk(r Result, mode FailMode) bool {
	switch mode {
	case FailNone:
		return false
	case FailExpiring:
		return r.expiring
	case FailRenewalFailing:
		return r.expiring || r.RenewalFailing
	case FailNonRenewable:
		return r.expiring || r.RenewalFailing || !r.Renewable
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
