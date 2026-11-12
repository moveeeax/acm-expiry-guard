package checker

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Resolver is the DNS lookup CheckDNS needs; *net.Resolver satisfies it.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// CNAMEProblemKind says what is wrong with a validation CNAME.
type CNAMEProblemKind string

const (
	// CNAMEMissing: the name does not resolve at all.
	CNAMEMissing CNAMEProblemKind = "missing"
	// CNAMEMismatch: the name resolves, but not to the value ACM expects.
	CNAMEMismatch CNAMEProblemKind = "mismatch"
	// CNAMELookupFailed: the lookup itself failed (timeout, SERVFAIL...).
	CNAMELookupFailed CNAMEProblemKind = "lookup failed"
)

// CNAMEProblem is one validation CNAME that did not check out.
type CNAMEProblem struct {
	Name string
	Kind CNAMEProblemKind
}

// CheckDNS resolves the validation CNAMEs of every issued Amazon certificate
// and records problems in Certificate.CNAMEProblems. A deleted validation
// CNAME means the next managed renewal fails, while ACM still reports the
// certificate as eligible. Each name is looked up once, with timeout as the
// per-lookup limit.
func CheckDNS(ctx context.Context, certs []Certificate, r Resolver, timeout time.Duration) {
	type answer struct {
		cname string
		err   error
	}
	cache := map[string]answer{}
	for i := range certs {
		c := &certs[i]
		if c.Type != "AMAZON_ISSUED" || c.Status != "ISSUED" {
			continue
		}
		c.CNAMEProblems = nil
		seen := map[string]bool{}
		for _, rec := range c.ValidationRecords {
			name := normalizeName(rec.Name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			a, ok := cache[name]
			if !ok {
				lctx, cancel := context.WithTimeout(ctx, timeout)
				a.cname, a.err = r.LookupCNAME(lctx, name)
				cancel()
				cache[name] = a
			}
			if kind, bad := classify(a.cname, a.err, rec.Value); bad {
				c.CNAMEProblems = append(c.CNAMEProblems, CNAMEProblem{Name: name, Kind: kind})
			}
		}
	}
}

func classify(cname string, err error, want string) (CNAMEProblemKind, bool) {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return CNAMEMissing, true
		}
		return CNAMELookupFailed, true
	}
	if normalizeName(cname) != normalizeName(want) {
		return CNAMEMismatch, true
	}
	return "", false
}

// normalizeName lowercases a DNS name and drops the trailing dot, so
// "_x.Example.com." and "_x.example.com" compare equal.
func normalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
