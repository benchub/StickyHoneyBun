# RDS online test harness

This directory contains the scripts that provision real AWS resources
(RDS Postgres + Lambda + IAM + SG + parameter groups), run assertions
against them, and tear everything down. The harness is invoked via
`make rds-test-online` from the repo root.

Unlike the docker-based test suite (which is purely local and free),
this one **costs real money** and runs against a real AWS account. A
single run is roughly $0.01 on a `db.t4g.micro`, but a leaked instance
left running burns ~$12/month. Read the cleanup story below before your
first run.

## Files

| File | Purpose |
|---|---|
| `preflight.py` | env-var validation, AWS session-time check, external-IP detection, stale-resource halt |
| `setup.py` | provisions every AWS resource (RDS primary + read replica, Lambda, IAM, SG, parameter groups), tagged with the run-id; writes `state-<run_id>.json` |
| `teardown.py` | tag-discovery-based cleanup; refuses to delete anything whose tag doesn't match |
| `list_orphans.py` | safety-net inspector — lists resources from any past test run still in AWS |
| `poll_alert.py` | polls Lambda's CloudWatch log group for a needle string |
| `run.pl` | entry point. Thin orchestrator: preflight → setup → `prove t/variants/rds/*.pl` → teardown |

The test files themselves live under `t/variants/rds/*.pl`; the helpers they call (`SHB_RDS.pm`, the cross-variant `SHB_Assertions.pm`, the self-hosted-only `SHB.pm`) all live together under `t/lib/`. See `t/variants/README.md` for the test-file conventions.

## Environment

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AWS_PROFILE` *or* the trio `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_SESSION_TOKEN` | yes | — | AWS credentials. Preflight verifies via `sts:GetCallerIdentity`. |
| `AWS_REGION` (or `AWS_DEFAULT_REGION`) | yes | — | Region for every created resource. |
| `SHB_TEST_VPC_ID` | yes | — | VPC where the RDS instance + security group land. |
| `SHB_TEST_SUBNET_IDS` | yes | — | Comma-separated; at least two in different AZs (RDS DB subnet group requirement). |
| `AWS_SESSION_EXPIRATION` | no | unset | ISO-8601 session expiry. If set, preflight enforces the `SHB_TEST_MIN_MINUTES` buffer. Most `AWS_PROFILE` setups don't populate this; that's fine, preflight just warns. |
| `SHB_TEST_MIN_MINUTES` | no | `10` | Required remaining-session buffer (only enforced when `AWS_SESSION_EXPIRATION` is set). |
| `SHB_TEST_INSTANCE_CLASS` | no | `db.t4g.micro` | RDS instance class. |
| `SHB_TEST_OPERATOR_IP` | no | auto-detected | Override for the SG ingress rule's source IP. Auto-detect uses `checkip.amazonaws.com` / `ipify.org` / `ifconfig.me`. |
| `SHB_TEST_TAGS` | no | empty | Extra `key=value,key=value` tags applied to every resource alongside the mandatory `sticky_honey_bun_test_id`. |
| `SHB_KEEP` | no | unset | When set to a non-empty value, the harness skips teardown on exit and leaves AWS resources in place. The end of the run prints the commands needed to either re-iterate or tear down. Inner-loop convenience only — never set this in CI. |
| `SHB_REUSE_RUN_ID` | no | unset | When set, the harness skips AWS provisioning entirely and reuses the existing RDS instance / Lambda / IAM / SG tagged with the given run-id. Only the extension reinstall step runs. Pair with `SHB_KEEP=1` to iterate against the same instance across many runs (saves ~12 minutes of RDS provisioning per iteration). |

## Cleanup paranoia (read before first run)

Every resource the harness creates carries two tags:

- `sticky_honey_bun_test_id=<run_id>` — uniqueness identifier
- `sticky_honey_bun_test_purpose="automated test — safe to delete"`

The harness enforces this at three layers:

1. **Preflight refuses to start** if any resource in the region already
   bears the `sticky_honey_bun_test_id` tag (regardless of value). A
   stale tag means a prior run leaked; clean it up first with
   `list_orphans.py` + `teardown.py`.
2. **Teardown re-verifies the tag** on every resource before issuing
   the delete API call. A mismatch is fatal; we never delete a
   resource whose tag doesn't match the expected run-id.
3. **The harness's `END {}` block always invokes teardown**, even on
   die / Ctrl-C / test failure. Belt-and-suspenders: if the END block
   itself fails, the operator gets a printed reminder of the run-id
   and the exact commands to run for manual cleanup.

If something goes wrong despite all that, `make rds-list-orphans` shows
everything across all past runs that still exists in AWS, with the
exact teardown command for each.

## Typical run

```sh
# 1. Get AWS creds into the env (assume_role, aws sso, vault, whatever)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
export AWS_SESSION_EXPIRATION=2026-05-25T18:30:00Z   # ISO 8601
export AWS_REGION=us-east-1

# 2. Tell the test where to land resources
export SHB_TEST_VPC_ID=vpc-0abcd1234
export SHB_TEST_SUBNET_IDS=subnet-0aaa,subnet-0bbb

# 3. Optional: add accounting tags
export SHB_TEST_TAGS="Owner=ben,CostCenter=eng,Env=test"

# 4. Go
make rds-test-online
```

Expect ~12-15 minutes wall time per run (RDS provisioning is the long
pole — the actual assertions are seconds).

## Iterating against a kept instance

For inner-loop development, the 12-minute RDS provisioning cost per run
is unworkable. The harness supports keeping a provisioned instance
across runs:

```sh
# First run: provision, run assertions, keep the resources on success/failure.
SHB_KEEP=1 make rds-test-online
# The run prints the run-id; capture it.

# Subsequent iterations: reuse the same RDS instance / Lambda / IAM / SG,
# only the extension reinstall + assertions run.
SHB_KEEP=1 SHB_REUSE_RUN_ID=<run-id-from-first-run> make rds-test-online

# When done iterating, tear down.
rds/online/.venv/bin/python3 rds/online/teardown.py <run-id>
```

Each reuse run drops and reinstalls the extension (idempotent schema
setup), so iterating on the extension SQL doesn't require recreating
the database. Inner-loop time drops from ~15 minutes to ~30 seconds
plus however long async Lambda + CloudWatch ingestion takes to surface
in `poll_alert` (typically under a minute on warm Lambda).

## When something doesn't tear down

```sh
make rds-list-orphans                                # see what's stuck
python3 rds/online/teardown.py <run-id-from-list>    # tear down by id
```

`teardown.py` is idempotent: running it on an already-cleaned run-id
is harmless.
