package checker

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// fakeResolver answers from a map and counts lookups, no network involved.
type fakeResolver struct {
	answers map[string]string
	errs    map[string]error
	calls   map[string]int
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[host]++
	if err, ok := f.errs[host]; ok {
		return "", err
	}
	if v, ok := f.answers[host]; ok {
		return v, nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestCheckDNS(t *testing.T) {
	issued := func(domain string, recs ...ValidationRecord) Certificate {
		return Certificate{Domain: domain, Type: "AMAZON_ISSUED", Status: "ISSUED", ValidationRecords: recs}
	}
	certs := []Certificate{
		issued("ok.example.com",
			ValidationRecord{Name: "_ok.example.com.", Value: "_v1.acm-validations.aws."},
			// wildcard SAN shares the apex record; looked up once
			ValidationRecord{Name: "_ok.example.com.", Value: "_v1.acm-validations.aws."},
		),
		issued("gone.example.com", ValidationRecord{Name: "_gone.example.com.", Value: "_v2.acm-validations.aws."}),
		issued("moved.example.com", ValidationRecord{Name: "_moved.example.com.", Value: "_v3.acm-validations.aws."}),
		issued("flaky.example.com", ValidationRecord{Name: "_flaky.example.com.", Value: "_v4.acm-validations.aws."}),
		// imported certs have no managed renewal to protect
		{Domain: "imported.example.com", Type: "IMPORTED", Status: "ISSUED",
			ValidationRecords: []ValidationRecord{{Name: "_imp.example.com.", Value: "_v5.acm-validations.aws."}}},
		// same record as the first cert: answered from the cache
		issued("ok2.example.com", ValidationRecord{Name: "_OK.example.com", Value: "_v1.acm-validations.aws"}),
	}
	res := &fakeResolver{
		answers: map[string]string{
			"_ok.example.com":    "_V1.acm-validations.aws.",
			"_moved.example.com": "_other.acm-validations.aws.",
		},
		errs: map[string]error{
			"_flaky.example.com": &net.DNSError{Err: "i/o timeout", Name: "_flaky.example.com", IsTimeout: true},
		},
	}

	CheckDNS(context.Background(), certs, res, time.Second)

	want := map[string][]CNAMEProblem{
		"ok.example.com":       nil,
		"gone.example.com":     {{Name: "_gone.example.com", Kind: CNAMEMissing}},
		"moved.example.com":    {{Name: "_moved.example.com", Kind: CNAMEMismatch}},
		"flaky.example.com":    {{Name: "_flaky.example.com", Kind: CNAMELookupFailed}},
		"imported.example.com": nil,
		"ok2.example.com":      nil,
	}
	for _, c := range certs {
		got := c.CNAMEProblems
		if len(got) != len(want[c.Domain]) {
			t.Errorf("%s: problems=%v want %v", c.Domain, got, want[c.Domain])
			continue
		}
		for i := range got {
			if got[i] != want[c.Domain][i] {
				t.Errorf("%s: problem %d = %v want %v", c.Domain, i, got[i], want[c.Domain][i])
			}
		}
	}
	if n := res.calls["_ok.example.com"]; n != 1 {
		t.Errorf("_ok.example.com looked up %d times, want 1", n)
	}
	if n := res.calls["_imp.example.com"]; n != 0 {
		t.Errorf("imported cert record looked up %d times, want 0", n)
	}
}

func TestClassifyNonDNSError(t *testing.T) {
	if kind, bad := classify("", errors.New("boom"), "x"); !bad || kind != CNAMELookupFailed {
		t.Errorf("classify(plain error) = %q, %v", kind, bad)
	}
}
