#!/bin/bash
#
# Manual smoke test for the RDS variant.
#
# This cannot run in CI because it requires a real RDS/Aurora cluster with
# pg_tle and aws_lambda installed, plus a target Lambda. Use this to validate
# a deployment after installing sticky_honey_bun_rds.
#
# Required env:
#   PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE
#   STICKY_HONEY_BUN_LAMBDA_ARN  - the Lambda ARN to invoke
#
# What it does:
#   1. Verifies pg_tle and aws_lambda extensions are installed.
#   2. Verifies sticky_honey_bun_rds extension is installed and the type exists.
#   3. Plants a honey row in a throwaway table.
#   4. Reads the honey row, which should trigger a Lambda invocation.
#   5. Cleans up.
#
# You verify Lambda receipt out-of-band (CloudWatch Logs, SQS, etc.) — this
# script cannot observe the side effect directly.

set -euo pipefail

: "${PGHOST:?must set PGHOST}"
: "${STICKY_HONEY_BUN_LAMBDA_ARN:?must set STICKY_HONEY_BUN_LAMBDA_ARN}"

PSQL="psql -v ON_ERROR_STOP=1 -X -A -t"

echo "==> Checking prerequisites"
$PSQL -c "SELECT 1 FROM pg_extension WHERE extname = 'pg_tle'"      | grep -q 1
$PSQL -c "SELECT 1 FROM pg_extension WHERE extname = 'aws_lambda'"  | grep -q 1
$PSQL -c "SELECT 1 FROM pg_extension WHERE extname = 'sticky_honey_bun_rds'" | grep -q 1
$PSQL -c "SELECT 1 FROM pg_type WHERE typname = 'honey_bun'"      | grep -q 1

echo "==> Configuring Lambda ARN in the locked-down config table"
# Idempotent: upsert so re-running the smoke test against an already-
# configured cluster doesn't trip the PK. PUBLIC has no access; we rely
# on the connecting role being the extension owner (or having explicit
# INSERT/UPDATE grants).
$PSQL <<SQL
INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config(key, value)
VALUES ('lambda_arn', '${STICKY_HONEY_BUN_LAMBDA_ARN}')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
SQL

echo "==> Planting a temporary honey row"
$PSQL <<SQL
CREATE TEMP TABLE shb_smoke (id int, honey honey_bun);
INSERT INTO shb_smoke VALUES (1, 'smoke_test.shb_smoke.honey');
SQL

echo "==> Triggering the trap"
$PSQL -c "SELECT * FROM shb_smoke WHERE id = 1" > /dev/null

echo "==> Done. Check the Lambda's CloudWatch log group for the event."
echo "    Expected payload tag: smoke_test.shb_smoke.honey"
