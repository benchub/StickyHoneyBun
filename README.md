# Sticky Honey Bun

![Sticky Honey Bun](yum.png)

Sticky Honey Bun is a PostgreSQL extension that gives you honeytokens in the form of a custom data type. Simply add a `honey_bun` column to any table(s) you want (the type can be renamed), put a non-null value into this column for any row(s) that you will never select, and 💥! You now have a trap for an attacker who comes in and does an unwary `SELECT * FROM table`.

Sticky Honey Bun alerts are simple - they just log information about who, what, where, when, etc. It is up to the alert processor to decide if the alert is legit and what action should be taken. Actions can be as simple as sending an email or as complicated as revoking the user access or locking everything down. Regardless, that processor lives outside of the DB, and is yours to craft as you desire.

## Quick example

```sql
CREATE EXTENSION sticky_honey_bun;
ALTER TABLE customers ADD COLUMN honey honey_bun;
INSERT INTO customers (email, honey)
VALUES ('do-not-touch@internal', 'public.customers.honey');
```

Now any `SELECT * FROM customers` that returns that row produces a
one-line JSON alert in the configured log file:

```json
{"ts":"2026-05-25T04:11:36.205673Z","event":"read_text","tag":"public.customers.honey","session_user":"alice","client_addr":"10.0.4.7","query":"SELECT * FROM customers"}
```

## End goals

- **Tripwire detection** for unauthorized reads of specific rows in PostgreSQL, without forcing queries through views or stored procedures.
- **Replica-safe**: side effects don't touch DB state, so traps can still fire on hot standbys.
- **Does not require logging all queries** which is often a non-starter on busy dbs.
- **Tamper-resistant** on self-hosted: the type I/O logic is in compiled C, not inspectable via `pg_proc.prosrc`.
- **Cheap on the common path**: NULL values short-circuit the type I/O functions entirely; non-trap rows pay nothing.
- **Self-describing alerts**: the stored value is itself a tag identifying which trap was tripped. Traps can live in as many tables and schemas as you desire.
- **Deadman-protected**: a heartbeat stream keeps the alert processor honest about whether silence means "no attacks" or "logger is broken."
- **Support for both self-hosted and hosted Postgres** by being flexible about the mechanics of the alert logging.

## Not goals
- **Protection against writes** from malicious users. Removing rows, encrypting data, dropping tables, or inserting poisoned values — Sticky Honey Bun doesn't care about any of that.
- **Replacing perimeter security.** Your database should be firewalled and have proper authentication and permission controls. By the time an attacker encounters Sticky Honey Bun, they're already inside the DB looking at real tables.
- **Protection against compromised admins.** If you can remove extensions, you can remove Sticky Honey Bun. OS-level activity — copying heap files, restoring backups elsewhere — is beyond what the extension can see.
- **Stopping exfiltration.** Detection is the goal; the `terminate_on_read` GUC is a best-effort circuit breaker (it halts the in-flight query at the next inter-row interrupt check) but it unmasks the trap to the attacker. Off by default.

## Where it sits in the landscape

Database deception is not a new field. Sticky Honey Bun occupies a
specific niche — *in-engine, column-level, read-time tripwire* — that
existing tools don't fill:

| Tool | What it is | Where it lives | Triggers on | Cost on common path |
|---|---|---|---|---|
| **Sticky Honey Bun** | column-level tripwire | inside real production tables | read of a planted honey row | ~0 |
| `pgAudit` | statement audit log | PG extension | every audited statement | per-statement overhead, plus analysis |
| Canarytokens (Thinkst) | external tokens (URLs, AWS keys, doc traps) | outside the DB | attacker *uses* the token later | 0 in-DB |
| FDW decoys (e.g. PG Decoy) | table-level decoys | foreign tables that look real | `SELECT` against the decoy | 0 if attacker ignores the decoy |
| Standalone DB honeypots | decoy database servers | separate infrastructure | attacker connects / explores | 0 (different system) |

These are not either/or. A layered setup runs `pgAudit` for the
compliance trail, Canarytokens for post-exfiltration detection, and
Sticky Honey Bun as the in-engine tripwire — three different attacker
behaviors caught by three different mechanisms. Sticky Honey Bun's
distinct contribution is **read-time detection inside real production
tables** with zero noise on application traffic: queries that don't
touch a planted row produce no log entries at all. The corollary is
that nothing fires until an attacker is already touching your real
data — which is exactly when you want to know.

## Repository layout

```
.
├── sticky_honey_bun.control       extension metadata
├── sql/                           install scripts for the self-hosted (C) variant
├── src/                           C source (honey_bun, logger, bgworker)
├── docker/                        Dockerfiles for build + test matrices
├── t/                             TAP tests
├── rds/                           RDS / Aurora variant (PL/pgSQL via pg_tle)
├── lambda/                        reference receiver Lambda for the RDS path
└── tools/                         alert monitor, external heartbeat poker
```

## How it works

`honey_bun` is a varlena (text-shaped) base type with four C I/O functions:

| Function | Side effect | Triggered by |
|---|---|---|
| `honey_bun_in`   | none         | INSERT, UPDATE, casts from cstring |
| `honey_bun_recv` | none         | Binary-protocol input |
| `honey_bun_out`  | logs alert   | Text-protocol read (most SELECTs, `COPY TO` text) |
| `honey_bun_send` | logs alert   | Binary-protocol read (`COPY TO BINARY`, some drivers, `pg_dump -Fc`) |

The I/O functions are marked `STRICT`, so PostgreSQL never invokes them for
NULL values — every legitimate row in a honey-bearing table pays zero overhead.

When a trap fires, the C logger opens the alert file
`O_WRONLY|O_APPEND|O_CREAT`, writes one JSON line, and closes. All errors
inside the logger are caught and swallowed so a broken log path cannot
propagate as a SELECT error (which would unmask the trap).

A background worker writes a heartbeat line at a configurable interval through
the same logger. Absence of heartbeats is the alert processor's signal that something
went wrong outside the trap's view.

## Log / event format

One JSON object per line (file) or per event (Lambda):

```json
{"ts":"2026-05-25T04:11:36.205673Z","event":"read_text","tag":"public.customers.honey","session_user":"alice","current_user":"alice","application_name":"psql","database":"prod","pid":23692,"client_addr":"10.0.4.7","query":"SELECT * FROM customers WHERE id = 3"}
```

| Field | Source | Purpose |
|---|---|---|
| `ts` | wall clock, UTC, ISO-8601 with microseconds | Forensics |
| `event` | `read_text`, `read_binary`, or `heartbeat` | Which path produced this event |
| `tag` | the stored value | Identifies which trap was triggered; `heartbeat` for the bgworker |
| `session_user` | authenticated identity | Primary alert processor filter key (immune to `SET ROLE`) |
| `current_user` | effective identity after `SET ROLE` | Detects role-switching shenanigans |
| `application_name` | session GUC | Forensic; spoofable via `PGAPPNAME`, do not filter on it |
| `database` | current DB | Forensics |
| `pid` | backend PID | Dedup, correlation with PG's own log |
| `client_addr` | `MyProcPort->raddr` | Primary alert processor filter key (paired with `session_user`) |
| `query` | `debug_query_string` | Forensics; can be NULL in some internal call paths |
| `cluster_id` | RDS variant only, set via the `sticky_honey_bun_rds_config` table (key `cluster_id`) | Identifies the source cluster when one Lambda fans many in |

Heartbeat lines carry only `ts`, `event` (always `"heartbeat"`), `tag`
(always `"heartbeat"`), and `pid`. The bgworker has no database
connection and no session, so the other fields are absent rather than
null:

```json
{"ts":"2026-05-25T04:11:36.205673Z","event":"heartbeat","tag":"heartbeat","pid":23692}
```

## Usage

The extension's install script revokes `USAGE` on the `honey_bun` type from `PUBLIC`,
so planting honey columns and inserting honey values require either the
extension-owner role (typically the superuser who ran `CREATE EXTENSION`)
or an explicit `GRANT USAGE ON TYPE honey_bun TO planter_role`. Reading
existing honey-bearing tables works for any role with `SELECT` and does
not require `USAGE`.

```sql
-- One-time install on self-hosted PG (as superuser).
CREATE EXTENSION sticky_honey_bun;

-- Plant a honey column on a sensitive table. Requires USAGE on the type;
-- the extension owner has this by default.
ALTER TABLE public.customers ADD COLUMN honey honey_bun;
CREATE INDEX idx_customer_honey ON public.customers (id) WHERE honey IS NOT NULL;

-- Insert the trap row. Every legitimate row keeps honey=NULL.
INSERT INTO customers (email, honey)
VALUES ('do-not-touch@internal', 'public.customers.honey');

-- Audit what's planted (superuser only by default — see below)
SELECT * FROM honey_bun_columns;

-- Verify behavior
-- no alert is triggered
SELECT * FROM customers WHERE honey IS NULL;

-- triggers an alert
SELECT * FROM customers WHERE honey is not null;
```

The honeytoken value is opaque to the extension — it's emitted verbatim
into the alert log's `tag` field. The recommended convention is
`schema.table.column`, which gives the alert processor and any audit
tooling a predictable shape to parse. Use whatever convention suits
your environment, just be consistent so downstream filtering stays
simple.

### Site-specific type names

The `honey_bun` name is public. An attacker who reads these docs can `\dT honey_bun` to find the trap type. To make planted columns less
discoverable, create site-specific aliases:

```sql
-- Register the alias type. Pick a name that fits your schema's vocabulary;
-- the more it looks like real data, the less it stands out to an attacker.
SELECT create_honey_bun_alias('account_token');
-- or in another schema:
SELECT create_honey_bun_alias('session_blob', 'auth');

-- Plant a column of the aliased type. The COLUMN name (auth_token) is
-- separate from the TYPE name (account_token); pick whichever combination
-- blends best with the surrounding columns.
ALTER TABLE customers ADD COLUMN auth_token account_token;
INSERT INTO customers (id, email, auth_token)
  VALUES (-1, 'do-not-touch@internal', 'public.customers.auth_token');
```

`create_honey_bun_alias` exists in **both the self-hosted and RDS variants**
with the same SQL surface. The mechanisms differ:

- **Self-hosted (C)**: each alias gets its own SQL-level I/O functions
  bound to the same compiled C symbols, plus a full set of comparison
  operators, btree/hash op classes, and `min`/`max` aggregates so
  `DISTINCT`/`ORDER BY`/`MIN`/`MAX`/`GROUP BY` all work on aliased columns.
- **RDS (pg_tle)**: each alias re-registers the type via
  `pgtle.create_base_type` pointing at the same PL/pgSQL I/O functions.
  A `honey_bun_registry` table tracks which types are honey-shaped so the
  `honey_bun_columns` view can find them.

Aliases trap identically to `honey_bun` and appear in `honey_bun_columns`.
On self-hosted, aliases depend on the extension's C functions; `DROP EXTENSION
sticky_honey_bun CASCADE` removes them along with everything else.

### Locked-down inventory

Sticky Honey Bun creates a view `honey_bun_columns` which enumerates every planted trap, including those under aliased type names. That is exactly the catalog an attacker who has landed in the database would want, so the install script revokes all access from `PUBLIC`. Only superusers (and the extension owner) can read it by default.

To give a narrow audit role access:

```sql
CREATE ROLE shb_audit;
GRANT SELECT ON honey_bun_columns TO shb_audit;
GRANT shb_audit TO your_audit_user;
```

This is a high bar, not an impenetrable one. The view's underlying query
(`pg_proc.prosrc = 'honey_bun_out'` joined against `pg_attribute` etc.)
can be reconstructed from public catalog reads by anyone determined enough
to look — but they have to know that's the symbol to look for. The
restricted view closes the opportunistic-attacker path.

## Self-hosted vs RDS

| Concern | Self-hosted | RDS / Aurora |
|---|---|---|
| Packaging | C extension | PL/pgSQL extension via `pg_tle` |
| Output sink | local file via C `write()` | `aws_lambda.invoke()` fire-and-forget |
| Replica support | yes (file I/O works on standbys) | yes (Lambda invoke is an external HTTP call) |
| Heartbeat source | extension bgworker | external poker (pg_cron is writer-only) |
| Tamper resistance | strong — function bodies are compiled | weak — PL bodies are readable in `pg_proc` |
| `honey_bun` SQL surface | identical | identical |
| `create_honey_bun_alias` | yes (full operators + aggregates per alias) | yes (alias type only) |
| `DISTINCT`/`ORDER BY`/`MIN`/`MAX` | yes | not without AWS extending pg_tle |
| Log JSON shape | identical | identical |

Both variants ship the same `honey_bun` type and emit the same JSON event
shape, so a single alert processor (a reference exists in `tools/alert_monitor.py`) handles both.

### Installing on RDS / Aurora

Prerequisites on the cluster:
- `pg_tle` extension (whitelist via `rds.allowed_extensions` /
  `aurora.allowed_extensions` parameter group, then `CREATE EXTENSION pg_tle`).
- `aws_lambda` extension.
- IAM role on the RDS instance with `lambda:InvokeFunction` on the target
  Lambda (deploy `lambda/handler.py`).

```sh
psql ... -f rds/sticky_honey_bun_rds.sql
psql ... -c "CREATE EXTENSION sticky_honey_bun_rds"

# Configure the Lambda ARN (and optional cluster_id) in the locked-down
# config table. Run as the extension owner — PUBLIC has no access.
psql ... <<SQL
INSERT INTO sticky_honey_bun_rds_config(key, value) VALUES
  ('lambda_arn', 'arn:aws:lambda:us-east-1:123456789012:function:my-shb'),
  ('cluster_id', 'prod-us-east-1')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
SQL
```

Then plant honey columns the same way as the self-hosted variant. Validate
with `rds/smoke_test.sh`.

## Configuration

Sticky Honey Bun must be loaded via `shared_preload_libraries` so its GUCs are
registered and the bgworker can register itself before any session starts.

```
shared_preload_libraries = 'sticky_honey_bun'
```

### GUCs (self-hosted)

| Name | Type | Default | Description |
|---|---|---|---|
| `sticky_honey_bun.log_path` | string | resolved from `log_directory` | Path to the alert file. Locked at server start to prevent a compromised superuser from redirecting writes (e.g. to `/dev/null`) via `ALTER SYSTEM`. Parent directory must exist. |
| `sticky_honey_bun.enabled` | bool | `on` | Master kill switch. Locked at server start so a compromised superuser session cannot disable the trap via `ALTER SYSTEM`. |
| `sticky_honey_bun.heartbeat_interval_seconds` | int (seconds) | `60` | Seconds between heartbeat lines from the bgworker. `0` disables heartbeats. Locked at server start to prevent runtime silencing. |
| `sticky_honey_bun.terminate_on_read` | bool | `off` | When `on`, a backend that reads a honey value is terminated (via SIGTERM) immediately after the alert is logged. Unmasks the trap to the attacker; in exchange the in-flight query halts at the next CHECK_FOR_INTERRUPTS. Only ordinary client backends are terminated — the heartbeat bgworker, parallel workers, and walsenders are spared. Locked at server start. |

All four GUCs are deliberately `PGC_POSTMASTER`: they can only be set in
`postgresql.conf` at server start. Changing them requires a real server
restart, which is auditable infrastructure activity rather than a quiet
`ALTER SYSTEM` call.

### Configuration (RDS variant)

`pg_tle` in RDS does not allow custom-namespace GUCs to be set durably. The RDS variant therefore
stores its configuration in a locked-down table:

```sql
CREATE TABLE sticky_honey_bun_rds_config (
    key   text PRIMARY KEY,
    value text
);
REVOKE ALL ON sticky_honey_bun_rds_config FROM PUBLIC;
```

| Key | Description |
|---|---|
| `lambda_arn` | ARN of the Lambda to invoke on trap events. Required for alerts to fire; absent or empty disables alerting (the trap returns the tag transparently). |
| `cluster_id` | Optional identifier emitted in the payload so a shared Lambda can route by source cluster. |

The output function `honey_bun_out_rds` runs `SECURITY DEFINER` and reads
this table as the extension owner. PUBLIC has no `SELECT`, `INSERT`,
`UPDATE`, or `DELETE` on the config table, so an attacker session cannot
read the Lambda ARN, cannot silence the trap by emptying it, and cannot
redirect alerts by overwriting it. Configuration changes go through the
extension owner.

The RDS variant intentionally has no `enabled` kill switch. To disable
the trap, `DROP EXTENSION sticky_honey_bun_rds` (auditable infrastructure
activity) or `DELETE FROM sticky_honey_bun_rds_config WHERE key =
'lambda_arn'` as the owner.

The RDS install script mirrors the self-hosted lockdown wherever the
mechanism translates from C to PL/pgSQL:

- `REVOKE EXECUTE` on `honey_bun_in_rds`, `honey_bun_out_rds`, and
  `create_honey_bun_alias`.
- `REVOKE USAGE` on the `honey_bun` type and on every alias created by
  `create_honey_bun_alias`.
- A `has_type_privilege` check inside `honey_bun_in_rds`.

That last check is load-bearing. PG's native typinput dispatch
bypasses function ACLs, and pg_tle's wrapper inherits the same
behavior — so the `REVOKE EXECUTE` on `honey_bun_in_rds` is not
enough on its own to block a forged cast. The in-function privilege
check is the PL/pgSQL analog of the C variant's `pg_type_aclcheck`
and closes the gap.

End result for operators: planter roles need an explicit `GRANT USAGE
ON TYPE honey_bun` (plus `GRANT EXECUTE ON FUNCTION honey_bun_in_rds`
in the RDS variant) to insert honey values. Reading existing honey-
bearing tables works for any role with `SELECT` — `USAGE` is checked
at CAST / CREATE time, not at result-row formatting time.

## Build

```sh
make help          # list targets
make local         # build against locally-installed PG (uses pg_config)
make install       # install to PG's pkglibdir / extension dir
make clean         # remove build artifacts
```

`PG_CONFIG` overrides the default `pg_config`:

```sh
PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config make local
```

### Multi-version build via docker

```sh
make docker-build-15      # build against PG 15 only
make docker-matrix        # build PG 14, 15, 16, 17, 18
make docker-clean         # remove tagged images
```

## Tests

TAP tests under `t/variants/self-hosted/*.pl` use `PostgreSQL::Test::Cluster` (PG 15+), which ships
with `postgresql-server-dev-N` on Debian but is **not** bundled with Homebrew's
PostgreSQL formula. Tests run inside docker for that reason. The PG 14
test module set was renamed (`PostgresNode` / `TestLib` →
`PostgreSQL::Test::Cluster` / `PostgreSQL::Test::Utils`); `t/lib/SHB.pm`
is a small shim that picks whichever is available, so the same tests run
on PG 14 through 18.

```sh
make docker-test-15        # run TAP suite against PG 15
make docker-test-matrix    # run against PG 15, 16, 17, 18
```

Each test file spins up an ephemeral cluster, configures the GUCs, runs the
behavior under test, and asserts against the log file or DB state.

### Coverage

| File | What it asserts |
|---|---|
| `t/variants/self-hosted/001_install.pl` | `CREATE EXTENSION` registers the type; log-path GUC honored |
| `t/variants/self-hosted/002_null_bypass.pl` | NULL honey values produce no log output |
| `t/variants/self-hosted/003_text_trip.pl` | Text-protocol reads emit `read_text` with expected JSON fields |
| `t/variants/self-hosted/004_binary_trip.pl` | `COPY TO BINARY` exercises `typsend`, emits `read_binary` |
| `t/variants/self-hosted/005_pg_dump_trip.pl` | `pg_dump` fires the trap; logged query shows the `COPY` |
| `t/variants/self-hosted/006_tag_discrimination.pl` | Distinct planted tags produce distinct log entries |
| `t/variants/self-hosted/007_kill_switch.pl` | `enabled = off` suppresses entries; re-enabling resumes them |
| `t/variants/self-hosted/008_inventory.pl` | `honey_bun_columns` view tracks planted columns and DROPs |
| `t/variants/self-hosted/009_heartbeat.pl` | Bgworker emits heartbeats; setting interval to 0 stops them |
| `t/variants/self-hosted/010_alias_type.pl` | `create_honey_bun_alias()` makes a site-specific type that traps identically and shows up in the inventory |
| `t/variants/self-hosted/011_select_shapes.pl` | Trap fires for `SELECT *`, `WHERE`, `LIMIT`, `DISTINCT`, `MIN`/`MAX`, `GROUP BY`, `ORDER BY`; does not fire for `count(col)` or subqueries that project the column away |
| `t/variants/self-hosted/012_partial_index.pl` | `CREATE INDEX ... WHERE honey IS NOT NULL` succeeds on honey_bun and on aliased types; building the index does not fire the trap; indexed reads do |
| `t/variants/self-hosted/013_inventory_lockdown.pl` | Non-superusers cannot SELECT from `honey_bun_columns`; explicit GRANT to an audit role works |
| `t/variants/self-hosted/016_terminate_on_read.pl` | `terminate_on_read = on` kills the reading backend after the log line is written; heartbeat bgworker survives; `ALTER SYSTEM` + reload cannot enable it at runtime |
| `t/variants/self-hosted/017_query_injection.pl` | SQL-comment payloads shaped to forge a second JSON event (close-brace + open-brace sequences, embedded newlines, control chars) cannot corrupt the log: every line stays valid JSON with the legitimate `event`/`tag` values |
| `t/variants/self-hosted/018_io_function_acl.pl` | Direct calls to `honey_bun_out`/`honey_bun_send` (and the alias-generated `_out`/`_send`) are blocked for non-superusers with permission denied; the real trap fires via typeoutput dispatch regardless of the function ACL |
| `t/variants/self-hosted/019_log_path_frozen.pl` | Resolved log path is captured at postmaster start; runtime `ALTER SYSTEM SET log_directory` + `pg_reload_conf` cannot redirect subsequent alerts |
| `t/variants/self-hosted/020_log_symlink_refusal.pl` | If the log path is a symlink (e.g. an attacker swapped the file), `O_NOFOLLOW` refuses to open it and the symlink target is not written |
| `t/variants/self-hosted/021_multiline_queries.pl` | Multi-line queries — pretty-printed SQL, CTEs with tabs and newlines, newlines inside string literals, and multi-statement batches sent as a single `PQexec` — produce exactly one JSON line per trap event with the `query` field round-tripping verbatim through `\n`/`\t` escaping |
| `t/variants/self-hosted/022_json_in_queries.pl` | SQL carrying JSON-shaped content (string literals containing JSON, JSONB casts, dollar-quoted JSON, JSON with backslash escapes, adversarial forge-shaped payloads) cannot escape its `query` string-value container; the outer alert object's `event`/`tag` stay legitimate and the query field round-trips byte-for-byte |
| `t/variants/self-hosted/023_type_usage_acl.pl` | Non-superusers cannot cast to `honey_bun` (or an alias type) or create a column of that type, closing the indirect forge primitive where an attacker would otherwise plant their own honey row to fire the trap with chosen tag; `GRANT USAGE` re-enables planting for a named role |
| `t/variants/self-hosted/024_field_injection.pl` | The alert object's non-`query` user-influenced fields (`tag` from planted honey values, `application_name` from session GUC) round-trip JSON-safely; embedded newlines, quotes, and forge-shaped bytes cannot hijack the outer object's `event` field |
| `t/variants/self-hosted/025_log_permission_denied.pl` | When the log path's parent directory is unwriteable (e.g. EACCES on `open()`), the trap query still succeeds with rows returned and no extension-shaped error leaks to the client; alerts resume cleanly once writability is restored |
| `t/variants/self-hosted/026_log_rotation.pl` | Renaming or deleting the live log file (the pattern logrotate's `create` mode uses) is handled cleanly: the next trap event recreates the file at the configured path and does not touch the rotated copy |
| `t/variants/self-hosted/027_red_team.pl` | Adversarial playbook against every defense layer (direct-call REVOKE, USAGE revoke, type-system USAGE check, PGC_POSTMASTER lock on `enabled`, frozen log_path, inventory-view lockdown). Asserts each attack vector fails AND that the legitimate read-path trap still fires |
| `t/variants/self-hosted/028_streaming_replica.pl` | Primary + streaming hot-standby in one TAP file: trap fires on the standby via typeoutput dispatch and writes to the standby's own log file, the primary's log is not touched, and the standby is verified to actually be in recovery |
| `t/variants/self-hosted/029_logical_replication.pl` | Publisher + subscriber: the subscription's apply worker materializes honey rows via `honey_bun_recv` (passing the C-level USAGE check when the subscription owner has USAGE) and subsequent subscriber-side reads fire the trap on the subscriber's own log |
| `t/variants/self-hosted/030_utf8_and_encoding.pl` | Multi-byte UTF-8 (Japanese, emoji, Cyrillic, Greek, Arabic, diacritics) in `tag` and in `query` round-trip verbatim through `escape_json`; all standard log fields are present on every line (field-stability regression guard) |
| `t/variants/self-hosted/031_recon_paths.pl` | Documents the recon paths open to a non-superuser (`pg_type`, `pg_proc.prosrc`, `pg_attribute` joins reconstruct the inventory) and the one closed path (`honey_bun_columns` view). Pins both states so future hardening or accidental loosening shows up as test churn |
| `t/variants/self-hosted/032_bgworker_resilience.pl` | Heartbeat bgworker is alive and emitting at the configured interval — heartbeat-emission is the only externally observable liveness signal because the SHMEM-only worker does not appear in `pg_stat_activity` |
| `t/variants/self-hosted/033_heartbeat_no_db.pl` | Heartbeat bgworker holds no database connection: dropping the `postgres` database does not break it; heartbeats continue and carry only the minimal `ts`/`event`/`tag`/`pid` fields appropriate for a process beacon |
| `t/variants/self-hosted/034_logical_replication_acls.pl` | Negative-path complement to `t/variants/self-hosted/029_*.pl`: subscription owner without `USAGE` on `honey_bun` stalls the apply worker (the C-level `pg_type_aclcheck` in `honey_bun_recv` fires from the replication path, not just direct casts); `GRANT USAGE` recovers the subscription |

The RDS variant has a manual smoke test (`rds/smoke_test.sh`) since it
requires a real RDS/Aurora cluster with `pg_tle` and `aws_lambda`.

### Online RDS test (real AWS resources)

`rds/online/` provisions a real RDS instance + Lambda + IAM + security
group in your AWS account, runs the assertions that map across from the
self-hosted suite, then tears everything down. Costs a few cents per
run. See `rds/online/README.md` for the env-var contract and the
multi-layer cleanup story (tag-based discovery, refuse-if-tag-mismatch
delete, always-fire `END {}` block, `make rds-list-orphans` safety net).

```sh
# Once your AWS creds + VPC/subnet are in the env:
make rds-test-online
```

### TDD discipline

New functionality starts with a failing test under `t/`. Run with
`make docker-test-15` for inner-loop feedback. Tests that don't care about
heartbeats should set `sticky_honey_bun.heartbeat_interval_seconds = 0` in
their cluster config to keep the log file deterministic.

### Extension upgrade discipline

The extension is currently at version 1.0; changes to `sql/sticky_honey_bun--1.0.sql`
are made in place because nothing has been tagged for release yet. Once 1.0
is tagged, any subsequent schema / ACL / function-signature change MUST ship
a `sql/sticky_honey_bun--1.0--1.1.sql` (etc.) upgrade script and bump
`default_version` in `sticky_honey_bun.control`. `ALTER EXTENSION sticky_honey_bun UPDATE`
on a deployed cluster will otherwise fail to apply later hardening changes
(REVOKEs, new GUCs, new C-level checks) — leaving production clusters
in a weaker state than fresh installs.

## Tools

### `tools/alert_monitor.py`

Reference alert processor. Tails the alert file, parses JSON events, applies
suppression rules, tracks heartbeat freshness, and on a real alert revokes
login and terminates the offending role's sessions on the configured primary.

```sh
python3 tools/alert_monitor.py --config alert_monitor.yaml
```

See `tools/alert_monitor.example.yaml`. Default `dry_run: true` — flip to
`false` once suppression rules are validated.

### `tools/heartbeat_poker.sh`

Periodically reads a designated heartbeat row from one or more PG endpoints,
generating heartbeat log lines on replicas where the bgworker can't run (RDS).
The alert processor's deadman watches for absence of these.

```sql
-- Once per cluster (on the writer)
CREATE TABLE shb_heartbeat (id int PRIMARY KEY, honey honey_bun);
INSERT INTO shb_heartbeat
  VALUES (1, 'sticky_honey_bun.heartbeat.external_poker');
```

```sh
SHB_POKER_INTERVAL=30 \
  ./tools/heartbeat_poker.sh \
  "postgresql://poker@replica1.example/postgres" \
  "postgresql://poker@replica2.example/postgres"
```

### `tools/sticky_honey_bun.logrotate`

Drop-in `logrotate.d` config for the alert file. The extension's
`open/write/close` per event means logrotate's default `create` mode works
without any SIGHUP / fd-reopen choreography — see the file's header comment
for the details. Install with:

```sh
cp tools/sticky_honey_bun.logrotate /etc/logrotate.d/sticky_honey_bun
```

and edit the path on the first line to match your `sticky_honey_bun.log_path`.

## Operations

### Forensics / incident response

When a real alert fires, the JSON line carries everything an IR needs to
start digging. Walking it field by field:

| Field | What it tells you |
|---|---|
| `ts` | UTC microsecond timestamp — joinable with PG's own `csvlog`/`jsonlog` |
| `session_user` | the authenticated identity — immune to `SET ROLE`, so it survives the obvious pivot |
| `current_user` | the *effective* identity after any `SET ROLE` — if `≠ session_user`, that's a red flag |
| `application_name` | spoofable via `PGAPPNAME`; use as a weak signal only |
| `database` + `pid` | the join keys for correlating with PG's `log_line_prefix` / `csvlog` for surrounding-session activity |
| `client_addr` | source IP — keep in mind proxies (PgBouncer, RDS Proxy) rewrite this to the proxy's address |
| `tag` | which trap was hit. The recommended `schema.table.column` convention makes this self-describing |
| `query` | the SQL text that triggered the read — can be NULL for some internal call paths (replication apply, autovacuum-adjacent code) |

Recommended correlation: enable PG's own `log_line_prefix` with `%m %p %u
%d %a %h` and `log_statement = 'mod'` (or higher) before incidents
happen. When a trap fires, join on `pid` + the session window around `ts`
to see what else the attacker did in the same session.

### PII and retention

The alert log can legitimately contain personal data:
- `client_addr` is an IP address.
- `session_user` can be a real person's identity if your roles are
  per-user.
- `query` carries arbitrary SQL text — it may contain literal email
  addresses, names, account numbers, etc. from `WHERE` clauses or
  string literals.

Treat the alert log as PII-bearing for retention purposes. Specifically:
- Apply the same retention schedule as your other audit logs (typically
  90 days to 7 years depending on jurisdiction and use case).
- A GDPR/CCPA right-to-erasure request that touches the subject's
  identifiers may require redaction of historical alerts.
- The extension provides no built-in tamper-evidence on the local log
  file — see the next section for why and for what to do about it.

### Durability and tamper-evidence

The local alert log is best-effort. In-file cryptographic integrity
(hash chains, signatures) is deliberately *not* implemented because the
threat model doesn't make it useful:

- An attacker with write access to the log file is already either the
  `postgres` OS user or root, which means they can read every heap file
  in `DataDir` directly. They don't need to bother going through the
  trap; they `cp -r $PGDATA/base/...` and bypass SQL entirely. The
  tampered log records no event they ever fired.
- A SQL-level attacker can't reach the file at all — the REVOKEs and
  C-level USAGE checks documented above close off the forge primitive
  from their reach.

Real durability and compliance-grade tamper-evidence come from shipping
each alert line to an external append-only sink as it's written. The
extension's job ends at "one JSON line on disk"; everything past that is
the operator's choice of pipeline.

Common shipping options, roughly ordered by integration cost:

**Third-party log SaaS** — Observe, Sumo Logic, Splunk Cloud, Datadog,
Honeycomb, Logz.io, New Relic Logs, etc. The vendor's agent (or a
generic `fluent-bit` / `vector`) tails `sticky_honey_bun.log` and ships
over HTTPS. Turnkey; full-text search and alerting included; no infra to
maintain. Costs scale with ingest volume — a bulk `pg_dump` of a
honey-bearing table inflates that meaningfully, so verify the vendor's
billing model and confirm their retention has an immutability /
append-only mode if you care about compliance.

**AWS CloudWatch Logs** — `cloudwatch-agent` or `awslogs` tails the file
and writes to a log group. IAM-gated, supports metric filters for
alarms, and retention is per-log-group. Note CloudWatch on its own
isn't strictly immutable; if you need write-once semantics, pair it
with a subscription filter that delivers to S3 with object lock.

**S3 with object lock (compliance mode)** — Rotate the local file
(logrotate's `dateext` works fine) and upload each rotation to a
versioned, object-locked bucket. Cheapest at high volume and gives
genuine write-once retention. The trade-off is that the
event-to-shipped latency is the rotation interval, so this is good for
the durable archive but should be paired with something real-time
(a SaaS or CloudWatch tail) for live alerting.

**Remote syslog / rsyslog / journald forwarding** — local `rsyslog`
reads the file via `imfile` and forwards to a remote collector or
SIEM. Standard Linux tooling, near-zero cost, good fit for on-prem.
Use TCP/TLS via RFC 5425 or RELP in production — the default UDP path
is lossy and unauthenticated.

**Self-hosted log stack** — Elasticsearch + Filebeat, Loki + Promtail,
Vector + ClickHouse, etc. Full control, no per-GB SaaS bill, you also
own the cluster's storage and retention story (including whatever
immutability guarantees your backend gives you).

Whichever sink you pick, two operational properties matter more than
the brand:

- **Append-only / write-once at the sink itself.** The whole point is
  that an attacker who can corrupt the local file cannot reach the
  sink. A SaaS that lets the customer delete arbitrary lines via the
  UI doesn't satisfy this; a sink with role-based deletion that
  requires a second human (or that's literally write-once at the
  storage layer) does.
- **Shipping latency under burst load.** A bulk read of a
  honey-bearing table produces one event per row. If the shipper
  buffers or backpressures during the burst, that's the window during
  which a tamper would go unrecorded on the durable side. Pick a sink
  whose ingest characteristics handle your worst-case burst, and
  size the local-file rotation around the same number.

### Capacity guidance

Rough planning numbers:
- A typical alert line is ~500 bytes of JSON (well-formed but not minified).
- A long `debug_query_string` (multi-KB ORM output, big `IN` lists,
  embedded blobs) can push a single line into the multi-KB range; `t/variants/self-hosted/014_*.pl`
  exercises 16 KB lines successfully.
- Heartbeats at the default `heartbeat_interval_seconds = 60` produce
  ~1,440 lines/day ≈ ~700 KB/day ≈ ~250 MB/year.
- A `pg_dump` of a 100M-row honey-bearing table will produce 100M alert
  lines (one per row). Budget accordingly, and suppress at the alert
  processor via `session_user` + `client_addr` matching the known dump
  role/host.

Plan log rotation by size, not interval. The shipped logrotate config
(`tools/sticky_honey_bun.logrotate`) defaults to size-based with a
weekly fallback.

### Common configuration mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| `sticky_honey_bun.enabled = off` left in postgresql.conf from a test | trap fires silently produce no log entries | flip back to `on` (or unset; default is `on`); a regression test like `t/variants/self-hosted/007_*.pl` catches the runtime-bypass attempt but won't catch a misset baseline |
| `sticky_honey_bun.log_path` unset and the system `log_directory` doesn't point where you expected | alerts land somewhere weird | always set `log_path` explicitly; macOS Homebrew is the most common surprise |
| `heartbeat_interval_seconds = 0` in production | the deadman never trips, so a silent logger looks like silence | use the default (`60`) unless you have a specific reason |
| `terminate_on_read = on` enabled by surprise | legitimate scans (audits, ORM batch jobs) terminate connections | enable only after rehearsing with non-production traffic |
| Forgot to `GRANT USAGE ON TYPE honey_bun` to a non-superuser planter role | `INSERT INTO honey_table` fails with `permission denied for type` | grant USAGE to the specific planter role; the trap mechanism itself does not need USAGE |
| Subscriber replicating a honey-bearing table without USAGE on the subscriber cluster | the apply worker errors out and the subscription stalls | grant USAGE on the subscriber to whichever role owns the subscription |

## Roadmap

| Item | Status | Notes |
|---|---|---|
| `honey_bun` type + side-effecting I/O | done | self-hosted (C) |
| JSON log line | done | shared by both variants |
| Docker build matrix (PG 14-18) | done | |
| Docker TAP test suite (PG 14-18) | done | 10 test files, 33 assertions |
| Alpine-based build images | done | ~750MB vs ~1.8GB on Debian |
| Site-specific type aliases | done | `create_honey_bun_alias()` |
| Cross-architecture builds | done | `DOCKER_PLATFORM=linux/amd64` etc. |
| Heartbeat background worker | done | self-hosted only |
| Kill-switch GUC | done | `sticky_honey_bun.enabled` |
| `honey_bun_columns` inventory view | done | catalog-driven, no separate registry |
| RDS / Aurora PL/pgSQL variant | done (untested in CI) | requires `pg_tle` + `aws_lambda` |
| External heartbeat poker | done | `tools/heartbeat_poker.sh` |
| Reference alert monitor | done | `tools/alert_monitor.py` |
| Reference receiver Lambda | done | `lambda/handler.py` |
| RDS variant end-to-end CI | not started | needs LocalStack or live AWS; manual smoke test exists |
| Backup-orchestrator cross-check | not started | alert processor currently filters by role + IP only |
| pgaudit-style integration | maybe | unclear if it adds value over the current mechanism |
| Helper for planting standard honey columns | maybe | nice ergonomic, not load-bearing |

## Things to be aware of

- **pg_dump trips the trap.** By design — the log captures the dump, and the
  alert processor is responsible for suppressing it via `session_user` and
  `client_addr` matching the known backup role and host. Do *not* filter on
  `application_name`; it is spoofable via the `PGAPPNAME` environment variable.

- **Logical replication trips the trap on the publisher.** Same as pg_dump:
  suppressed at the alert processor by the walsender's role.

- **Streaming/physical replication does not trip it.** Physical replicas ship
  WAL, not formatted row values, so `typoutput`/`typsend` is not invoked
  during replication. The trap only fires on actual *reads* on the replica.

- **Output function errors are silently swallowed.** A broken log path,
  permissions issue, or disk-full condition will not surface as a SELECT
  error. This is intentional — surfacing errors would unmask the trap. The
  trade-off is that you can lose alerts silently, which is exactly what
  heartbeats and the deadman are for.

- **I/O functions are declared `IMMUTABLE`** even though they have a
  filesystem side effect. PG's docs define IMMUTABLE as "does not modify
  the database and always returns the same result for the same input" —
  both still hold: we write to a file, not DB state, and the output
  cstring is determined entirely by the input value. This silences the
  `should not be volatile` CREATE TYPE warning. The one edge case is that
  a SQL-level call like `SELECT honey_bun_out('x'::honey_bun)` on a
  constant argument may be folded at plan time and fire the trap once
  instead of N times — but the executor's typeoutput dispatch path
  (normal SELECT/COPY/pg_dump) does not fold, so this is not a real risk
  in practice.

- **The log file's parent directory must exist.** The extension creates the
  file but does not `mkdir -p` its parents. The default
  resolution chain may point at a directory that does not exist (because
  `log_directory` is set but `logging_collector` is off). Set
  `sticky_honey_bun.log_path` explicitly in production.

- **The log file is owned by the postgres OS user.** Configure your log
  shipper to read it via group membership rather than running as root.

- **The bgworker has no database connection.** It writes heartbeat lines
  directly via the alert path — no session, no transaction, no syscache
  access. Two operational consequences: heartbeat lines carry only
  `ts`/`event`/`tag`/`pid` (the other JSON fields are absent, not null),
  and the worker does NOT appear in `pg_stat_activity` — heartbeat
  emission is the only externally observable liveness signal.

- **`sticky_honey_bun.enabled = off` mutes heartbeats too.** The same
  master switch gates both trap events and the bgworker's heartbeat. That
  can look like a deadman alert at the monitor if you forget. Tests that
  flip the kill switch should also disable heartbeats explicitly.

- **ORM/driver awareness is limited.** Most drivers treat `honey_bun` as an
  unknown OID and either error or fall back to text. For honey columns this
  is fine because no application code should be reading them anyway.

- **Logical replication subscribers need the extension AND `USAGE` on
  `honey_bun`.** The subscriber's table needs the type to exist
  (otherwise the column definition is invalid), and the apply worker
  needs `USAGE` to materialize incoming row values via `honey_bun_recv`
  (the C-level `pg_type_aclcheck` fires for the subscription role like
  any other caller). `GRANT USAGE` on the subscriber to whichever role
  owns the subscription.

- **`terminate_on_read` only fires from ordinary client backends.** Parallel
  workers and walsenders execute the same type I/O code but are spared the
  SIGTERM, so logical replication keeps flowing on the publisher and parallel
  plans don't deadlock partway through. The alert still fires from those
  paths; only the termination is suppressed. In practice the leader is where
  result-row typoutput runs for a normal `SELECT *`, so the exfiltration case
  is covered.

- **The `honey_bun_out` function may be invoked more than once per row.**
  PostgreSQL does not guarantee exactly-once invocation of `typoutput`. Treat
  log entries as "at least one access," not a precise count. Dedup at the
  alert processor using `pid` and the transaction start.

- **The RDS variant's PL/pgSQL bodies are readable** via `pg_proc`. Anyone
  with `pg_read_all_data` (which `rds_superuser` has) can inspect them. This
  is a hard limitation of running in managed Postgres; for tamper resistance
  use the self-hosted variant.

## License

Sticky Honey Bun is released under the PostgreSQL License — the same
permissive license PostgreSQL itself ships under. Full text in `LICENSE`.
