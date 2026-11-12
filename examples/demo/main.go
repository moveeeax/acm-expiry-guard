// Command demo renders acm-expiry-guard's output against a fixed set of
// fabricated certificates, so you can see the table and JSON without AWS
// credentials. Run it with:
//
//	go run ./examples/demo            # table
//	go run ./examples/demo -json      # JSON
package main

import (
	"flag"
	"os"
	"time"

	"github.com/moveeeax/acm-expiry-guard/internal/checker"
)

func main() {
	asJSON := flag.Bool("json", false, "emit JSON instead of a table")
	flag.Parse()

	// A fixed "now" keeps the demo output stable.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(days int) *time.Time { t := now.Add(time.Duration(days) * 24 * time.Hour); return &t }

	certs := []checker.Certificate{
		{ARN: "arn:aws:acm:eu-west-1:111122223333:certificate/imported", Domain: "legacy.example.com", Region: "eu-west-1",
			NotAfter: at(4), Type: "IMPORTED", RenewalEligibility: "INELIGIBLE", Status: "ISSUED", InUseBy: []string{"arn:aws:elasticloadbalancing:eu-west-1:...:loadbalancer/app/legacy"}},
		{ARN: "arn:aws:acm:us-east-1:111122223333:certificate/edge", Domain: "www.example.com", Region: "us-east-1",
			NotAfter: at(12), Type: "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE", Status: "ISSUED", InUseBy: []string{"arn:aws:cloudfront::...:distribution/E123"}},
		{ARN: "arn:aws:acm:us-east-1:111122223333:certificate/stuck", Domain: "shop.example.com", Region: "us-east-1",
			NotAfter: at(45), Type: "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE", Status: "ISSUED", InUseBy: []string{"arn:aws:elasticloadbalancing:us-east-1:...:loadbalancer/app/shop"},
			RenewalStatus: "PENDING_VALIDATION", RenewalValidations: []checker.DomainValidation{
				{Domain: "shop.example.com", Status: "SUCCESS"}, {Domain: "www.shop.example.com", Status: "PENDING_VALIDATION"}}},
		{ARN: "arn:aws:acm:us-east-1:111122223333:certificate/unused", Domain: "old.example.com", Region: "us-east-1",
			NotAfter: at(280), Type: "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE", Status: "ISSUED"},
		{ARN: "arn:aws:acm:us-east-1:111122223333:certificate/healthy", Domain: "api.example.com", Region: "us-east-1",
			NotAfter: at(240), Type: "AMAZON_ISSUED", RenewalEligibility: "ELIGIBLE", Status: "ISSUED", InUseBy: []string{"arn:aws:elasticloadbalancing:us-east-1:...:loadbalancer/app/api"}},
	}

	results := checker.Evaluate(certs, checker.Options{Days: 30, Now: now})
	if *asJSON {
		_ = checker.WriteJSON(os.Stdout, results)
		return
	}
	_ = checker.WriteTable(os.Stdout, results)
}
