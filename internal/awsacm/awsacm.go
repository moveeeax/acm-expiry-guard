// Package awsacm adapts the AWS Certificate Manager API to the checker.Lister
// interface. It is the only package that imports the AWS SDK, keeping the core
// logic testable without live credentials.
package awsacm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/moveeeax/acm-expiry-guard/internal/checker"
)

// api is the slice of the ACM client this adapter needs; narrowing it keeps the
// dependency surface small.
type api interface {
	ListCertificates(ctx context.Context, in *acm.ListCertificatesInput, opts ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, opts ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// Client lists ACM certificates region by region using the caller's default
// AWS configuration (env, shared config, IAM role — whatever the SDK resolves).
type Client struct {
	cfg    aws.Config
	newAPI func(region string) api
}

// New loads the default AWS config and returns a Lister.
func New(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg}
	c.newAPI = func(region string) api {
		return acm.NewFromConfig(cfg, func(o *acm.Options) { o.Region = region })
	}
	return c, nil
}

// List returns every certificate in one region.
func (c *Client) List(ctx context.Context, region string) ([]checker.Certificate, error) {
	client := c.newAPI(region)
	var out []checker.Certificate

	paginator := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, summary := range page.CertificateSummaryList {
			if summary.CertificateArn == nil {
				continue
			}
			cert, err := c.describe(ctx, client, region, *summary.CertificateArn)
			if err != nil {
				return nil, err
			}
			out = append(out, cert)
		}
	}
	return out, nil
}

func (c *Client) describe(ctx context.Context, client api, region, arn string) (checker.Certificate, error) {
	resp, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(arn)})
	if err != nil {
		return checker.Certificate{}, err
	}
	d := resp.Certificate
	cert := checker.Certificate{ARN: arn, Region: region}
	if d == nil {
		return cert, nil
	}
	cert.Domain = aws.ToString(d.DomainName)
	cert.NotAfter = d.NotAfter
	cert.Type = string(d.Type)
	cert.RenewalEligibility = string(d.RenewalEligibility)
	cert.Status = string(d.Status)
	cert.InUseBy = append(cert.InUseBy, inUse(d)...)
	return cert, nil
}

func inUse(d *types.CertificateDetail) []string {
	out := make([]string, 0, len(d.InUseBy))
	out = append(out, d.InUseBy...)
	return out
}
