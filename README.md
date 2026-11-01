# acm-expiry-guard

[![ci](https://github.com/moveeeax/acm-expiry-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/acm-expiry-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit AWS Certificate Manager (ACM) certificate expiry across every region and
**fail your pipeline before TLS silently lapses.**

AWS auto-renews DNS-validated certificates that are in use — but that guarantee
has holes. Certificates imported from outside ACM never auto-renew, certs whose
validation CNAME was deleted go stale, and certs attached to nothing won't renew
either. When one lapses, the first signal is an angry pager. `acm-expiry-guard`
turns that into a check you run on every deploy.

## What it does

- Lists ACM certificates across all — or a chosen subset of — regions,
  for every key algorithm (RSA 1024–4096 and ECDSA P-256/P-384/P-521).
- For each cert reads `NotAfter`, `Type` (`AMAZON_ISSUED` vs `IMPORTED`),
  `RenewalEligibility`, and `InUseBy`.
- Flags certificates **expiring** within a threshold (default 30 days) and
  certificates that will **not auto-renew** (imported, ineligible, or unused).
- Prints a table sorted soonest-expiry-first, or `--json` for machines.
- **Exits non-zero** when a certificate breaches the threshold, so it gates CI.

## Install

```sh
go install github.com/moveeeax/acm-expiry-guard/cmd/acm-expiry-guard@latest
```

Or build from source: `go build -o acm-expiry-guard ./cmd/acm-expiry-guard`.

Requires Go 1.26 or newer.

## Usage

Credentials are resolved the standard AWS way (`AWS_PROFILE`, environment,
instance role, SSO — anything the SDK understands). The tool only needs
`acm:ListCertificates` and `acm:DescribeCertificate`.

```sh
# Two regions, fail the build if anything expires within 30 days
acm-expiry-guard --regions us-east-1,eu-west-1 --days 30 --fail-on expiring

# Every commercial region, machine-readable
acm-expiry-guard --all-regions --json
```

Sample table output ([full fixture](examples/sample-table.txt)):

```text
DOMAIN              REGION     TYPE      DAYS LEFT  RENEWABLE  IN USE  EXPIRES     REASON
legacy.example.com  eu-west-1  imported  4          no         yes     2026-01-05  expires soon; imported (no auto-renew)
www.example.com     us-east-1  amazon    12         yes        yes     2026-01-13  expires soon
api.example.com     us-east-1  amazon    240        yes        yes     2026-08-29  ok
old.example.com     us-east-1  amazon    280        no         no      2026-10-08  not in use
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--regions` | `AWS_REGION` or `us-east-1` | Comma-separated regions to scan |
| `--all-regions` | `false` | Scan all 34 commercial regions (see below) |
| `--days` | `30` | Expiry threshold in days |
| `--fail-on` | `expiring` | Exit-code trigger: `none`, `expiring`, or `non-renewable` |
| `--json` | `false` | Emit JSON instead of a table |

### Regions and opt-in

`--all-regions` scans the 34 regions of the standard `aws` partition listed in
the [AWS Regions table](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html)
(checked 2026-11-02). GovCloud and China are not included.

17 of them were launched after 2019-03-20 and are opt-in: `af-south-1`,
`ap-east-1`, `ap-east-2`, `ap-south-2`, `ap-southeast-3` through
`ap-southeast-7`, `ca-west-1`, `mx-central-1`, `eu-south-1`, `eu-south-2`,
`eu-central-2`, `il-central-1`, `me-south-1`, `me-central-1`. A call to a region
that is not enabled in the account fails, and the tool then exits with `2`. If
your account has not enabled every opt-in region, pass the regions you use with
`--regions` instead.

### Exit codes

- `0` — nothing tripped the `--fail-on` condition.
- `1` — at least one certificate is at risk under the chosen mode.
- `2` — usage or AWS error.

`--fail-on non-renewable` is stricter than `expiring`: it also fails on
certificates that AWS will never auto-renew, even if they aren't expiring yet —
useful for catching imported certs early.

## How it works

The AWS-facing code lives in one small package (`internal/awsacm`); everything
else — the evaluation rules, sorting, table/JSON rendering, and exit-code
logic — is provider-neutral and driven through a `Lister` interface. That means
the whole decision engine is unit-tested against a fake ACM API, with no live
AWS calls. See [`examples/demo`](examples/demo) for a runnable demonstration:

```sh
go run ./examples/demo         # table
go run ./examples/demo -json   # JSON
```

## CI gate

```yaml
- name: Guard ACM certs
  run: |
    go install github.com/moveeeax/acm-expiry-guard/cmd/acm-expiry-guard@latest
    acm-expiry-guard --all-regions --days 30 --fail-on expiring
```

## License

MIT — see [LICENSE](LICENSE).
