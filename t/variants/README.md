# TAP test layout

```
t/
├── lib/
│   ├── SHB.pm              self-hosted helpers (PostgreSQL::Test::Cluster shim)
│   ├── SHB_RDS.pm          RDS helpers (state load, connstr, schema setup, poll Lambda)
│   └── SHB_Assertions.pm   cross-variant assertion bodies
└── variants/
    ├── self-hosted/        TAP scripts for the C extension
    └── rds/                TAP scripts for the pg_tle / aws_lambda variant
```

## File-level conventions

Every test file follows the same pattern, regardless of variant:

1. **Variant header on line 1-2**:
   ```perl
   # Variants: self-hosted, rds
   ```
   `self-hosted` and `rds` are the only values today. Concerns that apply
   to both variants share the SAME number across both subdirectories
   (`001_install.pl` exists in both `self-hosted/` and `rds/`). RDS-only
   concerns start at 800.

2. **`use lib 't/lib'`** to pull in the helpers. Test files run from the
   repo root (`prove` is invoked there by both `make installcheck` and
   `rds/online/run.pl`).

3. **Shared assertion bodies** live in `t/lib/SHB_Assertions.pm`. The
   convention is that the assertion takes a `$run_psql` coderef so the
   caller wires up its variant's psql-runner:
   ```perl
   # self-hosted
   SHB_Assertions::assert_honey_bun_type_exists(
       sub { $node->psql('postgres', $_[0]) });

   # rds
   SHB_Assertions::assert_honey_bun_type_exists(
       sub { SHB_RDS::psql_run($cs, $_[0]) });
   ```
   Setup logic (cluster boot vs RDS provisioning) is variant-specific
   and stays out of the shared lib.

4. **`done_testing()`** at the bottom — no fixed plan count.

## Running the suites

Self-hosted (PG 14-18 via docker):
```sh
make docker-test-15
make docker-test-matrix
```

RDS (requires AWS creds; provisions real resources):
```sh
make rds-test-online
```

See `rds/online/README.md` for the env-var contract, cost notes, and
cleanup story for the RDS suite.

## Adding tests

For a new concern that applies to **only one variant**: add a single
file under that variant's directory. Use a number that doesn't collide
with the parallel-numbered shared concerns (RDS-only files start at
800 by convention).

For a new concern that applies to **both variants**: write the cross-
variant assertion body in `t/lib/SHB_Assertions.pm`, then add a per-
variant test file under each of `self-hosted/` and `rds/` that wires
up the variant's psql-runner and calls the shared assertion. Use the
same file number in both subdirectories.

## Coverage matrix

`✓` = test file exists. `—` = concern does not apply (mechanism
absent in that variant). `→NNN` = the concern maps to a different-
numbered test under the same number block.

| Concern | self-hosted | rds | Notes |
|---|:-:|:-:|---|
| 001 install | ✓ | ✓ | Shared: `assert_honey_bun_type_exists` |
| 002 null_bypass | ✓ | ✓ | STRICT typeoutput; RDS uses `count_alerts` + sentinel sync |
| 003 text_trip | ✓ | ✓ | Shared: `assert_text_trip` (full JSON-shape check) |
| 004 binary_trip | ✓ | ✓ | pg_tle base types have no typsend; `COPY ... TO STDOUT BINARY` errors with "no binary output function" and the trap is NOT fired. The RDS test documents this as the expected (and operationally-relevant) behavior |
| 005 pg_dump_trip | ✓ | ✓ | `pg_dump --data-only` against RDS dispatches typeoutput via COPY |
| 006 tag_discrimination | ✓ | ✓ | Direct port |
| 007 kill_switch | ✓ | →802 | RDS has no `enabled` GUC; uses `DELETE FROM sticky_honey_bun_rds_config` instead |
| 008 inventory | ✓ | ✓ | Shared: `assert_inventory_lists_columns` (schema-filtered) |
| 009 heartbeat | ✓ | →803 | No bgworker on RDS; uses external `tools/heartbeat_poker.sh` |
| 010 alias_type | ✓ | ✓ | `create_honey_bun_alias` works in both variants |
| 011 select_shapes | ✓ | partial | RDS pg_tle lacks per-alias operators/aggregates, so `DISTINCT`/`ORDER BY`/`MIN`/`MAX`/`GROUP BY` shapes are not exercised |
| 012 partial_index | ✓ | ✓ | Index build uses typcmp (not typeoutput) — silent in both variants |
| 013 inventory_lockdown | ✓ | ✓ | Shared: `assert_inventory_locked_from_role` |
| 014 long_query | ✓ | ✓ | 16 KB query padding fits in both the local log line and Lambda's 256 KB async-invocation payload |
| 015 concurrent_writes | ✓ | — | Concurrency semantics are the same; not exercised on a managed `db.t4g.micro` for cost |
| 016 terminate_on_read | ✓ | — | RDS has no `terminate_on_read` (the C extension's PGC_POSTMASTER bool); no analog mechanism in pg_tle |
| 017 query_injection | ✓ | ✓ | Shared: `assert_alert_fields`; JSON-corrupting comment bytes |
| 018 io_function_acl | ✓ | ✓ | Shared: `assert_io_function_call_denied`; `honey_bun_out_rds` vs `honey_bun_out` / `honey_bun_send` |
| 019 log_path_frozen | ✓ | →804 | No log file on RDS; the analog tamper-resistance check is the locked-down config table |
| 020 log_symlink_refusal | ✓ | — | No log file on RDS |
| 021 multiline_queries | ✓ | ✓ | Direct port |
| 022 json_in_queries | ✓ | ✓ | Direct port |
| 023 type_usage_acl | ✓ | ✓ | Shared: `assert_cast_to_type_denied` + `assert_create_column_of_type_denied` |
| 024 field_injection | ✓ | ✓ | Direct port; `tag` and `application_name` round-trip |
| 025 log_permission_denied | ✓ | ✓ | RDS analog: an unreachable Lambda (bogus `lambda_arn`). The `EXCEPTION WHEN OTHERS THEN NULL` block in `honey_bun_out_rds` keeps the failure invisible to the caller — SELECT succeeds, returns rows, no error reaches the client |
| 026 log_rotation | ✓ | — | No log file on RDS |
| 027 red_team | ✓ | partial | Vectors targeting self-hosted-only surfaces (`ALTER SYSTEM`, GUC kill switch, `log_directory`) are not applicable to RDS |
| 028 streaming_replica | ✓ | →805 | The harness now provisions a read replica alongside the primary. The RDS-side concern is captured by 805 (a richer test that uses the replica as setup and pins the `server_addr` field as the per-node identifier) |
| 029 logical_replication | ✓ | — | Logical-rep orchestration across two RDS instances not yet wired |
| 030 utf8_and_encoding | ✓ | ✓ | Direct port; multi-byte UTF-8 in `tag` + `query` + `application_name` |
| 031 recon_paths | ✓ | adapt | RDS additionally documents that `pg_proc.prosrc` exposes the full PL/pgSQL body — an asymmetry vs the C variant that the README discusses |
| 032 bgworker_resilience | ✓ | — | No bgworker on RDS |
| 033 heartbeat_no_db | ✓ | — | No bgworker on RDS |
| 034 logical_replication_acls | ✓ | — | Same as 029 |
| 801 cluster_id | — | ✓ | RDS-only: per-database config-table `cluster_id` differentiation |
| 802 config_kill_switch | — | ✓ | RDS-only: `DELETE FROM sticky_honey_bun_rds_config` silences the trap (parallels 007) |
| 803 external_heartbeat | — | ✓ | RDS-only: `tools/heartbeat_poker.sh` against the cluster produces alerts (parallels 009) |
| 804 config_tamper_resistance | — | ✓ | RDS-only: app role cannot SELECT/UPDATE/DELETE/INSERT on the config table; SECURITY DEFINER read by the trap function still works (parallels 019) |
| 805 server_addr | — | ✓ | RDS-only: the alert payload's `server_addr` field identifies which node within a cluster fired the trap (primary vs read replica). `cluster_id` is shared across nodes because the config table is WAL-replicated, so `server_addr` is the load-bearing per-node identifier |
