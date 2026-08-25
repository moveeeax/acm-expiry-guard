package awsacm

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// fakeAPI stands in for the ACM client so the adapter's mapping and pagination
// can be tested without AWS.
type fakeAPI struct {
	pages   [][]types.CertificateSummary
	details map[string]*types.CertificateDetail
	call    int
}

func (f *fakeAPI) ListCertificates(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	out := &acm.ListCertificatesOutput{CertificateSummaryList: f.pages[f.call]}
	if f.call < len(f.pages)-1 {
		token := "next"
		out.NextToken = &token
	}
	f.call++
	return out, nil
}

func (f *fakeAPI) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	return &acm.DescribeCertificateOutput{Certificate: f.details[*in.CertificateArn]}, nil
}

func TestListMapsFieldsAcrossPages(t *testing.T) {
	notAfter := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{
		pages: [][]types.CertificateSummary{
			{{CertificateArn: aws.String("arn:a")}},
			{{CertificateArn: aws.String("arn:b")}},
		},
		details: map[string]*types.CertificateDetail{
			"arn:a": {
				DomainName:         aws.String("a.example.com"),
				NotAfter:           &notAfter,
				Type:               types.CertificateTypeAmazonIssued,
				RenewalEligibility: types.RenewalEligibilityEligible,
				Status:             types.CertificateStatusIssued,
				InUseBy:            []string{"arn:elb/a"},
			},
			"arn:b": {
				DomainName:         aws.String("b.example.com"),
				NotAfter:           &notAfter,
				Type:               types.CertificateTypeImported,
				RenewalEligibility: types.RenewalEligibilityIneligible,
				Status:             types.CertificateStatusIssued,
			},
		},
	}
	c := &Client{newAPI: func(string) api { return fake }}

	certs, err := c.List(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs across 2 pages, want 2", len(certs))
	}

	a := certs[0]
	if a.Domain != "a.example.com" || a.Region != "us-east-1" {
		t.Errorf("cert a domain/region = %q/%q", a.Domain, a.Region)
	}
	if a.Type != "AMAZON_ISSUED" || a.RenewalEligibility != "ELIGIBLE" {
		t.Errorf("cert a type/eligibility = %q/%q", a.Type, a.RenewalEligibility)
	}
	if len(a.InUseBy) != 1 || a.InUseBy[0] != "arn:elb/a" {
		t.Errorf("cert a InUseBy = %v", a.InUseBy)
	}
	if a.NotAfter == nil || !a.NotAfter.Equal(notAfter) {
		t.Errorf("cert a NotAfter = %v want %v", a.NotAfter, notAfter)
	}

	b := certs[1]
	if b.Type != "IMPORTED" || len(b.InUseBy) != 0 {
		t.Errorf("cert b type/inuse = %q/%v", b.Type, b.InUseBy)
	}
}
