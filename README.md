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
  `RenewalEligibility`, `InUseBy`, and the managed renewal state
  (`RenewalSummary.RenewalStatus` and per-domain `ValidationStatus`).
- Flags certificates **expiring** within a threshold (default 30 days),
  certificates that will **not auto-renew** (imported, ineligible, or unused),
  and certificates whose **managed renewal is stuck** (`PENDING_VALIDATION` or
  `FAILED`).
- With `--check-dns`, resolves each DNS validation CNAME and reports missing
  or wrong ones before ACM's next renewal attempt trips over them.
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
`acm:ListCertificates` and `acm:DescribeCertificate`. `--check-dns` queries the
system's DNS resolvers and needs no AWS permissions.

```sh
# Two regions, fail the build if anything expires within 30 days
acm-expiry-guard --regions us-east-1,eu-west-1 --days 30 --fail-on expiring

# Every commercial region, machine-readable
acm-expiry-guard --all-regions --json

# Also fail on stuck renewals and deleted validation CNAMEs
acm-expiry-guard --all-regions --check-dns --fail-on renewal-failing
```

Sample table output ([full fixture](examples/sample-table.txt)):

```text
DOMAIN              REGION     TYPE      DAYS LEFT  RENEWABLE  IN USE  EXPIRES     REASON
legacy.example.com  eu-west-1  imported  4          no         yes     2026-01-05  expires soon; imported (no auto-renew)
www.example.com     us-east-1  amazon    12         yes        yes     2026-01-13  expires soon
shop.example.com    us-east-1  amazon    45         yes        yes     2026-02-15  renewal stuck: PENDING_VALIDATION (www.shop.example.com PENDING_VALIDATION)
api.example.com     us-east-1  amazon    240        yes        yes     2026-08-29  ok
old.example.com     us-east-1  amazon    280        no         no      2026-10-08  not in use
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--regions` | `AWS_REGION` or `us-east-1` | Comma-separated regions to scan |
| `--all-regions` | `false` | Scan all 34 commercial regions (see below) |
| `--days` | `30` | Expiry threshold in days |
| `--fail-on` | `expiring` | Exit-code trigger: `none`, `expiring`, `renewal-failing`, or `non-renewable` |
| `--check-dns` | `false` | Resolve each DNS validation CNAME and report missing or wrong ones |
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

Each mode includes the ones before it:

- `expiring` fails on certificates inside the `--days` window.
- `renewal-failing` also fails on certificates whose managed renewal is stuck
  or whose validation CNAME is missing (see below), even if they aren't
  expiring yet.
- `non-renewable` also fails on certificates that AWS will never auto-renew —
  useful for catching imported certs early.

### Stuck renewals

ACM starts a managed renewal 45 days before expiry for public certificates
and 60 days for private ones, and reports it in `RenewalSummary`
([renewal status docs](https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html)). A DNS-validated cert whose validation CNAME was deleted keeps
`RenewalEligibility=ELIGIBLE`, so the eligibility check alone misses it. The
tool reads the renewal status and adds a reason:

- `PENDING_VALIDATION` or `FAILED`: `renewal stuck: <status>`, followed by
  ACM's failure reason (if any) and the domains whose validation is not
  `SUCCESS`, e.g.
  `renewal stuck: PENDING_VALIDATION (www.shop.example.com PENDING_VALIDATION)`.
  The JSON output sets `renewal_failing: true` and `renewal_status`.
- `PENDING_AUTO_RENEWAL` (ACM is still validating on its own; AWS says no
  action is required) and `SUCCESS` are not flagged. If a renewal stays pending until the `--days` window, the
  expiry check catches it.

`--check-dns` finds the broken record before the renewal starts. For every
issued Amazon certificate it looks up each validation record name and expects
a CNAME to the value ACM gave. Reasons:

- `validation CNAME missing: <name>`: the name does not resolve.
- `validation CNAME mismatch: <name>`: it resolves, but to something else.
- `validation CNAME lookup failed: <name>`: timeout or server error. This is
  reported but does not set `renewal_failing`, since it says nothing about the
  record itself.

Each lookup has a 5-second timeout. Records in a private hosted zone only
resolve from inside the VPC, so run `--check-dns` where those zones are
visible.

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
