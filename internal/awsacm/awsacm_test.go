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
	inputs  []*acm.ListCertificatesInput
}

func (f *fakeAPI) ListCertificates(_ context.Context, in *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	f.inputs = append(f.inputs, in)
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

// ACM's default ListCertificates filter returns only RSA_1024 and RSA_2048
// certificates; every request must ask for all key algorithms explicitly.
func TestListRequestsEveryKeyType(t *testing.T) {
	fake := &fakeAPI{
		pages:   [][]types.CertificateSummary{{}, {}},
		details: map[string]*types.CertificateDetail{},
	}
	c := &Client{newAPI: func(string) api { return fake }}

	if _, err := c.List(context.Background(), "us-east-1"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(fake.inputs) != 2 {
		t.Fatalf("got %d ListCertificates calls, want 2", len(fake.inputs))
	}
	want := types.KeyAlgorithm("").Values()
	for i, in := range fake.inputs {
		if in.Includes == nil {
			t.Fatalf("call %d: Includes is nil, ACM would return RSA_1024/RSA_2048 only", i)
		}
		got := map[types.KeyAlgorithm]bool{}
		for _, k := range in.Includes.KeyTypes {
			got[k] = true
		}
		for _, k := range want {
			if !got[k] {
				t.Errorf("call %d: KeyTypes missing %s", i, k)
			}
		}
	}
	for _, k := range []types.KeyAlgorithm{types.KeyAlgorithmEcPrime256v1, types.KeyAlgorithmRsa4096} {
		found := false
		for _, v := range want {
			found = found || v == k
		}
		if !found {
			t.Errorf("KeyAlgorithm.Values() lacks %s", k)
		}
	}
}

func TestListMapsRenewalSummaryAndValidationRecords(t *testing.T) {
	record := &types.ResourceRecord{
		Name:  aws.String("_x.a.example.com."),
		Type:  types.RecordTypeCname,
		Value: aws.String("_y.acm-validations.aws."),
	}
	fake := &fakeAPI{
		pages: [][]types.CertificateSummary{{{CertificateArn: aws.String("arn:a")}}},
		details: map[string]*types.CertificateDetail{
			"arn:a": {
				DomainName:         aws.String("a.example.com"),
				Type:               types.CertificateTypeAmazonIssued,
				RenewalEligibility: types.RenewalEligibilityEligible,
				Status:             types.CertificateStatusIssued,
				DomainValidationOptions: []types.DomainValidation{
					{DomainName: aws.String("a.example.com"), ValidationMethod: types.ValidationMethodDns, ValidationStatus: types.DomainStatusSuccess, ResourceRecord: record},
					{DomainName: aws.String("mail.example.com"), ValidationMethod: types.ValidationMethodEmail, ValidationStatus: types.DomainStatusSuccess},
				},
				RenewalSummary: &types.RenewalSummary{
					RenewalStatus:       types.RenewalStatusFailed,
					RenewalStatusReason: types.FailureReasonCaaError,
					DomainValidationOptions: []types.DomainValidation{
						{DomainName: aws.String("a.example.com"), ValidationMethod: types.ValidationMethodDns, ValidationStatus: types.DomainStatusFailed, ResourceRecord: record},
						{DomainName: aws.String("mail.example.com"), ValidationMethod: types.ValidationMethodEmail, ValidationStatus: types.DomainStatusPendingValidation},
					},
				},
			},
		},
	}
	c := &Client{newAPI: func(string) api { return fake }}

	certs, err := c.List(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	a := certs[0]
	if a.RenewalStatus != "FAILED" || a.RenewalStatusReason != "CAA_ERROR" {
		t.Errorf("renewal status/reason = %q/%q", a.RenewalStatus, a.RenewalStatusReason)
	}
	if len(a.RenewalValidations) != 2 ||
		a.RenewalValidations[0].Domain != "a.example.com" || a.RenewalValidations[0].Status != "FAILED" ||
		a.RenewalValidations[1].Domain != "mail.example.com" || a.RenewalValidations[1].Status != "PENDING_VALIDATION" {
		t.Errorf("RenewalValidations = %+v", a.RenewalValidations)
	}
	// Email validation has no record; the DNS record appears in both lists.
	if len(a.ValidationRecords) != 2 {
		t.Fatalf("ValidationRecords = %+v, want the DNS record twice", a.ValidationRecords)
	}
	for _, r := range a.ValidationRecords {
		if r.Domain != "a.example.com" || r.Name != "_x.a.example.com." || r.Value != "_y.acm-validations.aws." {
			t.Errorf("ValidationRecord = %+v", r)
		}
	}
}

func TestListWithoutRenewalSummary(t *testing.T) {
	fake := &fakeAPI{
		pages: [][]types.CertificateSummary{{{CertificateArn: aws.String("arn:b")}}},
		details: map[string]*types.CertificateDetail{
			"arn:b": {DomainName: aws.String("b.example.com"), Type: types.CertificateTypeImported},
		},
	}
	c := &Client{newAPI: func(string) api { return fake }}
	certs, err := c.List(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if b := certs[0]; b.RenewalStatus != "" || b.RenewalValidations != nil || b.ValidationRecords != nil {
		t.Errorf("imported cert got renewal data: %+v", b)
	}
}
