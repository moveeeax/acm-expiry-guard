// Command acm-expiry-guard audits ACM certificate expiry across AWS regions and
// exits non-zero when a certificate breaches the danger window, so it doubles
// as a CI gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/moveeeax/acm-expiry-guard/internal/awsacm"
	"github.com/moveeeax/acm-expiry-guard/internal/checker"
)

// defaultRegions is the standard set of commercial AWS regions scanned with
// --all-regions. It intentionally omits GovCloud and China partitions.
var defaultRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"ca-central-1", "sa-east-1",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"me-south-1", "af-south-1",
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("acm-expiry-guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		regionsCSV = fs.String("regions", "", "comma-separated regions to scan (default: AWS_REGION or us-east-1)")
		allRegions = fs.Bool("all-regions", false, "scan every standard commercial region")
		days       = fs.Int("days", 30, "expiry threshold in days")
		failOn     = fs.String("fail-on", "expiring", "what turns the exit code red: none|expiring|non-renewable")
		asJSON     = fs.Bool("json", false, "emit JSON instead of a table")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: acm-expiry-guard [flags]\n\nAudit ACM certificate expiry across AWS regions.\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	mode := checker.FailMode(*failOn)
	switch mode {
	case checker.FailNone, checker.FailExpiring, checker.FailNonRenewable:
	default:
		fmt.Fprintf(stderr, "invalid --fail-on %q (want none|expiring|non-renewable)\n", *failOn)
		return 2
	}

	regions := resolveRegions(*regionsCSV, *allRegions)
	if len(regions) == 0 {
		fmt.Fprintln(stderr, "no regions to scan")
		return 2
	}

	ctx := context.Background()
	lister, err := awsacm.New(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "aws config: %v\n", err)
		return 2
	}

	var certs []checker.Certificate
	for _, region := range regions {
		got, err := lister.List(ctx, region)
		if err != nil {
			fmt.Fprintf(stderr, "list %s: %v\n", region, err)
			return 2
		}
		certs = append(certs, got...)
	}

	results := checker.Evaluate(certs, checker.Options{Days: *days})
	if *asJSON {
		if err := checker.WriteJSON(stdout, results); err != nil {
			fmt.Fprintf(stderr, "write json: %v\n", err)
			return 2
		}
	} else {
		if err := checker.WriteTable(stdout, results); err != nil {
			fmt.Fprintf(stderr, "write table: %v\n", err)
			return 2
		}
	}

	return checker.ExitCode(results, mode)
}

func resolveRegions(csv string, all bool) []string {
	if all {
		return defaultRegions
	}
	if csv != "" {
		var out []string
		for _, r := range strings.Split(csv, ",") {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		return out
	}
	if env := os.Getenv("AWS_REGION"); env != "" {
		return []string{env}
	}
	return []string{"us-east-1"}
}
