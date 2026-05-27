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
| 004 binary_trip | ✓ | ✓ | self-hosted: `honey_bun_send` (typsend) is registered, so `COPY BINARY` succeeds and the trap fires with `event=read_binary`; RDS: pg_tle base types have no typsend, so `COPY ... TO STDOUT BINARY` errors with "no binary output function" before typeoutput dispatch — the trap is NOT fired, and the RDS test documents this as the expected (and operationally-relevant) limitation |
| 005 pg_dump_trip | ✓ | ✓ | `pg_dump --data-only` against RDS dispatches typeoutput via COPY |
| 006 tag_discrimination | ✓ | ✓ | Direct port |
| 007 kill_switch | ✓ | →802, →806 | RDS has no GUC; 802 tests the "remove the destination" kill (`DELETE lambda_arn`); 806 tests the explicit `enabled=off` kill, which is the closer analog to self-hosted's `sticky_honey_bun.enabled` GUC |
| 008 inventory | ✓ | ✓ | Shared: `assert_inventory_lists_columns` (schema-filtered) + `assert_dropped_column_removed_from_inventory` |
| 009 heartbeat | ✓ | →803 | No bgworker on RDS; uses external `tools/heartbeat_poker.sh` |
| 010 alias_type | ✓ | ✓ | Shared: `assert_alias_type_registered`, `assert_inventory_lists_columns`; `create_honey_bun_alias` works in both variants |
| 011 select_shapes | ✓ | partial | RDS pg_tle lacks per-alias operators/aggregates, so `DISTINCT`/`ORDER BY`/`MIN`/`MAX`/`GROUP BY` shapes are not exercised |
| 012 partial_index | ✓ | ✓ | self-hosted: index build on the honey column uses typcmp (not typeoutput) — silent, via `assert_partial_index_build_silent`; RDS: pg_tle has no btree opclass for honey_bun, so the RDS test indexes a scalar column with a `honey IS NOT NULL` predicate — the path is different but typeoutput is still not invoked |
| 013 inventory_lockdown | ✓ | ✓ | Shared: `assert_inventory_locked_from_role` |
| 014 long_query | ✓ | ✓ | 16 KB query padding fits in both the local log line and Lambda's 256 KB async-invocation payload |
| 015 concurrent_writes | ✓ | ✓ | Self-hosted asserts flock prevents log-line interleaving; RDS asserts N concurrent reads each produce their own CloudWatch event (no Lambda Event-mode drops at modest concurrency) |
| 016 terminate_on_read | ✓ | — | RDS has no `terminate_on_read` (the C extension's PGC_POSTMASTER bool); no analog mechanism in pg_tle |
| 017 query_injection | ✓ | ✓ | Shared: `assert_alert_fields`; JSON-corrupting comment bytes |
| 018 io_function_acl | ✓ | ✓ | Shared: `assert_io_function_call_denied`; `honey_bun_out_rds` vs `honey_bun_out` / `honey_bun_send` |
| 019 log_path_frozen | ✓ | →804 | No log file on RDS; the analog tamper-resistance check is the locked-down config table |
| 020 log_symlink_refusal | ✓ | — | No log file on RDS |
| 021 multiline_queries | ✓ | ✓ | Direct port |
| 022 json_in_queries | ✓ | ✓ | Direct port |
| 023 type_usage_acl | ✓ | ✓ | Shared: `assert_cast_to_type_denied`; self-hosted tests CREATE TABLE denial inline (with log-size invariant); RDS calls `assert_create_column_of_type_denied` |
| 024 field_injection | ✓ | ✓ | Direct port; `tag` and `application_name` round-trip |
| 025 log_permission_denied | ✓ | ✓ | RDS analog: an unreachable Lambda (bogus `lambda_arn`). The `EXCEPTION WHEN OTHERS THEN NULL` block in `honey_bun_out_rds` keeps the failure invisible to the caller — SELECT succeeds, returns rows, no error reaches the client |
| 026 log_rotation | ✓ | — | No log file on RDS |
| 027 red_team | ✓ | ✓ | Each variant runs the cross-variant attack vectors (direct calls, casts, CREATE TABLE, inventory enumeration) via the shared lib, plus its own variant-specific vectors: self-hosted adds the ALTER SYSTEM defenses (enabled-GUC flip, log_directory redirect); RDS adds the config-table tamper vectors (SELECT/UPDATE/DELETE/INSERT, kill-switch INSERT). Both end with the legitimate-read regression check |
| 028 streaming_replica | ✓ | →805 | The harness now provisions a read replica alongside the primary. The RDS-side concern is captured by 805 (a richer test that uses the replica as setup and pins the `server_addr` field as the per-node identifier) |
| 029 logical_replication | ✓ | — | Logical-rep orchestration across two RDS instances not yet wired |
| 030 utf8_and_encoding | ✓ | ✓ | Direct port; multi-byte UTF-8 in `tag` + `query` + `application_name` |
| 031 recon_paths | ✓ | adapt | RDS additionally documents that `pg_proc.prosrc` exposes the full PL/pgSQL body — an asymmetry vs the C variant that the README discusses |
| 032 bgworker_resilience | ✓ | — | No bgworker on RDS |
| 033 heartbeat_no_db | ✓ | — | No bgworker on RDS |
| 034 logical_replication_acls | ✓ | — | Same as 029 |
| 035 vacuum_analyze | ✓ | ✓ | Shared: `assert_maintenance_ops_silent`; ANALYZE and VACUUM walk the relation through typcmp / the storage layer, not typeoutput — neither fires the trap |
| 036 set_role_detection | ✓ | ✓ | Shared: `assert_set_role_reflected_in_alert`; after `SET ROLE`, the alert carries `session_user` (immune) and `current_user` (role-switched) separately. RDS variant reconstructs `current_user` via `current_setting('role')` because `honey_bun_out_rds` is SECURITY DEFINER and would otherwise report the function owner |
| 037 logical_rep_needs_extension | ✓ | — | Docker-only: subscriber without the extension cannot declare a `honey_bun` column; an operator who stubs the column as `text` to keep replication flowing creates an inert text-only mirror with no subscriber-side trap. Failure mode is in PG's type system, identical across variants — testing on RDS would require a second instance for no new coverage |
| 038 orm_reads | ✓ | — | Docker-only: invokes ORMs across three language ecosystems doing their natural "fetch row" idiom against a honey-bearing table. Each tester must fire the trap. Current set: Python (psycopg2 baseline, SQLAlchemy, Django ORM), Ruby (ActiveRecord), Node (Sequelize). Scripts live in `t/orm-testers/`; adding more is a matter of dropping a new file there + adding its language runtime / dep-install to `docker/Dockerfile.test` + an `@testers` entry in the driver. Each tester individually skips when its runtime / library isn't on PATH; the whole file skips only when ALL testers are unavailable |
| 801 cluster_id | — | ✓ | RDS-only: per-database config-table `cluster_id` differentiation |
| 802 config_kill_switch | — | ✓ | RDS-only: `DELETE FROM sticky_honey_bun.config` silences the trap (parallels 007) |
| 803 external_heartbeat | — | ✓ | RDS-only: `tools/heartbeat_poker.sh` against the cluster produces alerts (parallels 009) |
| 804 config_tamper_resistance | — | ✓ | RDS-only: app role cannot SELECT/UPDATE/DELETE/INSERT on the config table; SECURITY DEFINER read by the trap function still works (parallels 019) |
| 805 server_addr | — | ✓ | RDS-only: the alert payload's `server_addr` field identifies which node within a cluster fired the trap (primary vs read replica). `cluster_id` is shared across nodes because the config table is WAL-replicated, so `server_addr` is the load-bearing per-node identifier |
| 806 enabled_kill_switch | — | ✓ | RDS analog of self-hosted 007: the locked-down `sticky_honey_bun.config` row `enabled='off'` silences the trap; only the extension owner can flip it (an app role's UPDATE attempt is permission-denied) |
| 807 bytea_cast_denied | — | ✓ | RDS-only regression for the C1 finding in `REPORT.md`: pg_tle's `create_base_type` auto-registers a binary-compatible `pg_cast` between the new type and `bytea`, which would let `honey::bytea` silently reinterpret the bytes with zero typeoutput dispatch. The install body explicitly DROPs that cast in both directions; this test pins the absence — the `::bytea` cast now errors (no `pg_cast` entry, PG errors before typeoutput dispatch), data is not leaked, and the trap does NOT fire because typeoutput is never reached |
