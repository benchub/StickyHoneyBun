# Sticky Honey Bun

![Sticky Honey Bun](yum.png)

Sticky Honey Bun is a PostgreSQL extension that gives you honeytokens in the form of a custom data type. Simply add a new column of the type `honey_bun` to any table(s) you want, put a non-null value into this column for any row(s) that you will never select, and 💥! You now have a trap for an attacker who comes in and does an unwary `SELECT * FROM table`.

Sticky Honey Bun alerts are simple - they just log information about who, what, where, when, etc. It is up to the alert processor to decide if the alert is legit and what action should be taken. It can be as simple as sending an email or as complicated as revoking the user access or locking everything down. Regardless, that consumer lives outside of the DB, and is yours to craft as you desire.

## End goals

- **Tripwire detection** for unauthorized reads of specific rows in PostgreSQL, without forcing queries through views or stored procedures.
- **Replica-safe**: side effects don't touch DB state, so traps can still fire on hot standbys (where attackers often go).
- **Does not require logging all queries** which is often a non-starter on busy dbs.
- **Tamper-resistant** on self-hosted: the type I/O logic is in compiled C, not inspectable via `pg_proc.prosrc`.
- **Cheap on the common path**: NULL values short-circuit the type I/O functions entirely; non-trap rows pay nothing.
- **Self-describing alerts**: the stored value is itself a tag identifying which honey was tripped. A single shared type can plant traps in arbitrarily many tables.
- **Deadman-protected**: a heartbeat stream keeps the alert processor honest about whether silence means "no attacks" or "logger is broken."
- **Support for both self-hosted and hosted Postgres** by being flexible about the mechanics of the alert logging.

## Not goals
- **Protection against writes** from malicious users. Removing rows, encrypting data, or inserting poisoned values - Sticky Honey Bun doesn't care about any of that.
- **Unauthorized access**: Your database should be heavily firewalled and have a robust user authentication setup. Users should have proper permission controls. Sticky Honey Bun will not help with those defenses. By the time an attacker might encounter Sticky Honey Bun, they are already inside your database, accessing data.
- **Protection against compromised admins**: If you can remove extensions, you can remove Sticky Honey Bun.
- **Stopping exfiltration** is not a primary goal of Sticky Honey Bun, only detecting it and possibly taking action. If you have an attacker that can read a honeytoken, it is too late. The `terminate_on_read` GUC is a best-effort circuit breaker: when enabled, an in-flight bulk read is halted at the next inter-row interrupt check, so the leaked surface is bounded — but the trap is also unmasked to the attacker. Off by default.
- **OS-level exfiltration**, such as file copies or restoring backups to an unmanaged server, is well beyond anything Sticky Honey Bun can even know about, much less take action on.

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
| `cluster_id` | RDS variant only, set via `sticky_honey_bun_rds.cluster_id` GUC | Identifies the source cluster when one Lambda fans many in |

## Configuration

Sticky Honey Bun must be loaded via `shared_preload_libraries` so its GUCs are
registered and the bgworker can register itself before any session starts.

```
shared_preload_libraries = 'sticky_honey_bun'
```

### GUCs (self-hosted)

| Name | Type | Default | Description |
|---|---|---|---|---|
| `sticky_honey_bun.log_path` | string | resolved from `log_directory` | Path to the alert file. Locked at server start to prevent a compromised superuser from redirecting writes (e.g. to `/dev/null`) via `ALTER SYSTEM`. Parent directory must exist. |
| `sticky_honey_bun.enabled` | bool | `on` | Master kill switch. Locked at server start so a compromised superuser session cannot disable the trap via `ALTER SYSTEM`. |
| `sticky_honey_bun.heartbeat_interval_seconds` | int (seconds) | `60` | Seconds between heartbeat lines from the bgworker. `0` disables heartbeats. Locked at server start to prevent runtime silencing. |
| `sticky_honey_bun.terminate_on_read` | bool | `off` | When `on`, a backend that reads a honey value is terminated (via SIGTERM) immediately after the alert is logged. Unmasks the trap to the attacker; in exchange the in-flight query halts at the next CHECK_FOR_INTERRUPTS. Only ordinary client backends are terminated — the heartbeat bgworker, parallel workers, and walsenders are spared. Locked at server start. |

All four GUCs are deliberately `PGC_POSTMASTER`: they can only be set in
`postgresql.conf` at server start. Changing them requires a real server
restart, which is auditable infrastructure activity rather than a quiet
`ALTER SYSTEM` call.

### GUCs (RDS variant)

| Name | Description |
|---|---|
| `sticky_honey_bun_rds.lambda_arn` | ARN of the Lambda to invoke on trap events. Required. |
| `sticky_honey_bun_rds.cluster_id` | Optional identifier sent in the payload so a shared Lambda can route by source. |

The RDS variant intentionally has no `enabled` kill switch. pg_tle base
extensions cannot register GUCs with `PGC_POSTMASTER` context, so any
runtime-settable flag would be trivially bypassable by an attacker
(`SET sticky_honey_bun_rds.enabled = off`). To turn the RDS trap off,
`DROP EXTENSION sticky_honey_bun_rds`. The `lambda_arn` GUC has the same
exposure — a session can `SET sticky_honey_bun_rds.lambda_arn = ''` to
suppress alerts for its own queries — which is a hard limitation of the
pg_tle path. Defense in depth: keep the RDS role grants narrow so non-admin
sessions can't reach the catalog state.

The RDS install script mirrors the self-hosted variant's lockdown where the
mechanism translates: `REVOKE EXECUTE` on `honey_bun_in_rds`/`honey_bun_out_rds`
and on `create_honey_bun_alias`; `REVOKE USAGE` on the `honey_bun` type and
on every alias created by `create_honey_bun_alias`; and a `has_type_privilege`
check inside `honey_bun_in_rds` (the PL/pgSQL analog of the C variant's
`pg_type_aclcheck`, since pg_tle's typinput dispatch bypasses function ACLs
the same way PG's native typinput dispatch does). Planter roles need an
explicit `GRANT USAGE ON TYPE honey_bun` to insert honey values.

## Usage

The install script revokes `USAGE` on the `honey_bun` type from `PUBLIC`,
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

The value of the honeytoken is opaque to the extension — it's there as context for you, to emitted
verbatim into the alter log's `tag` field. The recommended convention is
`schema.table.column`, as it gives the alert processor and any audit
tooling a predictable shape to parse. But if that's not handy for your alert processor, pick whatever convention works for you.

### Locked-down inventory

`honey_bun_columns` enumerates every planted trap, including those under
aliased type names. That is exactly the catalog an attacker who has landed
in the database would want, so the install script revokes all access from
`PUBLIC`. Only superusers (and the extension owner) can read it by default.

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

### Site-specific type names

The `honey_bun` name is public. An attacker who reads these docs can
`\dT honey_bun` to find the trap type. To make planted columns less
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
| `DISTINCT`/`ORDER BY`/`MIN`/`MAX` | yes | not yet (no operators on PL-side types) |
| Log JSON shape | identical | identical |

Both variants ship the same `honey_bun` type and emit the same JSON event
shape, so a single alert processor (`tools/alert_monitor.py`) handles both.

### Installing on RDS / Aurora

Prerequisites on the cluster:
- `pg_tle` extension (whitelist via `rds.allowed_extensions` /
  `aurora.allowed_extensions` parameter group, then `CREATE EXTENSION pg_tle`).
- `aws_lambda` extension.
- IAM role on the RDS instance with `lambda:InvokeFunction` on the target
  Lambda (deploy `lambda/handler.py`).
- Custom GUCs `sticky_honey_bun_rds.lambda_arn` (required) and
  `sticky_honey_bun_rds.cluster_id` (optional) set in the parameter group.

```sh
psql ... -f rds/sticky_honey_bun_rds.sql
psql ... -c "CREATE EXTENSION sticky_honey_bun_rds"
```

Then plant honey columns the same way as the self-hosted variant. Validate
with `rds/smoke_test.sh`.

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

TAP tests under `t/*.pl` use `PostgreSQL::Test::Cluster` (PG 15+), which ships
with `postgresql-server-dev-N` on Debian but is **not** bundled with Homebrew's
PostgreSQL formula. Tests run inside docker for that reason.

```sh
make docker-test-15        # run TAP suite against PG 15
make docker-test-matrix    # run against PG 15, 16, 17, 18
```

Each test file spins up an ephemeral cluster, configures the GUCs, runs the
behavior under test, and asserts against the log file or DB state.

### Coverage

| File | What it asserts |
|---|---|
| `t/001_install.pl` | `CREATE EXTENSION` registers the type; log-path GUC honored |
| `t/002_null_bypass.pl` | NULL honey values produce no log output |
| `t/003_text_trip.pl` | Text-protocol reads emit `read_text` with expected JSON fields |
| `t/004_binary_trip.pl` | `COPY TO BINARY` exercises `typsend`, emits `read_binary` |
| `t/005_pg_dump_trip.pl` | `pg_dump` fires the trap; logged query shows the `COPY` |
| `t/006_tag_discrimination.pl` | Distinct planted tags produce distinct log entries |
| `t/007_kill_switch.pl` | `enabled = off` suppresses entries; re-enabling resumes them |
| `t/008_inventory.pl` | `honey_bun_columns` view tracks planted columns and DROPs |
| `t/009_heartbeat.pl` | Bgworker emits heartbeats; setting interval to 0 stops them |
| `t/010_alias_type.pl` | `create_honey_bun_alias()` makes a site-specific type that traps identically and shows up in the inventory |
| `t/011_select_shapes.pl` | Trap fires for `SELECT *`, `WHERE`, `LIMIT`, `DISTINCT`, `MIN`/`MAX`, `GROUP BY`, `ORDER BY`; does not fire for `count(col)` or subqueries that project the column away |
| `t/012_partial_index.pl` | `CREATE INDEX ... WHERE honey IS NOT NULL` succeeds on honey_bun and on aliased types; building the index does not fire the trap; indexed reads do |
| `t/013_inventory_lockdown.pl` | Non-superusers cannot SELECT from `honey_bun_columns`; explicit GRANT to an audit role works |
| `t/016_terminate_on_read.pl` | `terminate_on_read = on` kills the reading backend after the log line is written; heartbeat bgworker survives; `ALTER SYSTEM` + reload cannot enable it at runtime |
| `t/017_query_injection.pl` | SQL-comment payloads shaped to forge a second JSON event (close-brace + open-brace sequences, embedded newlines, control chars) cannot corrupt the log: every line stays valid JSON with the legitimate `event`/`tag` values |
| `t/018_io_function_acl.pl` | Direct calls to `honey_bun_out`/`honey_bun_send` (and the alias-generated `_out`/`_send`) are blocked for non-superusers with permission denied; the real trap fires via typeoutput dispatch regardless of the function ACL |
| `t/019_log_path_frozen.pl` | Resolved log path is captured at postmaster start; runtime `ALTER SYSTEM SET log_directory` + `pg_reload_conf` cannot redirect subsequent alerts |
| `t/020_log_symlink_refusal.pl` | If the log path is a symlink (e.g. an attacker swapped the file), `O_NOFOLLOW` refuses to open it and the symlink target is not written |
| `t/021_multiline_queries.pl` | Multi-line queries — pretty-printed SQL, CTEs with tabs and newlines, newlines inside string literals, and multi-statement batches sent as a single `PQexec` — produce exactly one JSON line per trap event with the `query` field round-tripping verbatim through `\n`/`\t` escaping |
| `t/022_json_in_queries.pl` | SQL carrying JSON-shaped content (string literals containing JSON, JSONB casts, dollar-quoted JSON, JSON with backslash escapes, adversarial forge-shaped payloads) cannot escape its `query` string-value container; the outer alert object's `event`/`tag` stay legitimate and the query field round-trips byte-for-byte |
| `t/023_type_usage_acl.pl` | Non-superusers cannot cast to `honey_bun` (or an alias type) or create a column of that type, closing the indirect forge primitive where an attacker would otherwise plant their own honey row to fire the trap with chosen tag; `GRANT USAGE` re-enables planting for a named role |
| `t/024_field_injection.pl` | The alert object's non-`query` user-influenced fields (`tag` from planted honey values, `application_name` from session GUC) round-trip JSON-safely; embedded newlines, quotes, and forge-shaped bytes cannot hijack the outer object's `event` field |
| `t/025_log_permission_denied.pl` | When the log path's parent directory is unwriteable (e.g. EACCES on `open()`), the trap query still succeeds with rows returned and no extension-shaped error leaks to the client; alerts resume cleanly once writability is restored |
| `t/026_log_rotation.pl` | Renaming or deleting the live log file (the pattern logrotate's `create` mode uses) is handled cleanly: the next trap event recreates the file at the configured path and does not touch the rotated copy |

The RDS variant has a manual smoke test (`rds/smoke_test.sh`) since it
requires a real RDS/Aurora cluster with `pg_tle` and `aws_lambda`.

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
  file but does not `mkdir -p` its parents. On macOS Homebrew PG the default
  resolution chain may point at a directory that does not exist (because
  `log_directory` is set but `logging_collector` is off). Set
  `sticky_honey_bun.log_path` explicitly in production.

- **The log file is owned by the postgres OS user.** Configure your log
  shipper to read it via group membership rather than running as root.

- **The bgworker connects to the `postgres` database.** Heartbeat events log
  the regular fields (which are mostly empty for the bgworker context, since
  there's no real session). If you've dropped the `postgres` database, the
  bgworker will fail to start.

- **The bgworker also calls `shb_log_event`**, so flipping
  `sticky_honey_bun.enabled = off` mutes heartbeats too. That can look like
  a deadman alert at the monitor if you forget. Tests that flip the kill
  switch should also disable heartbeats explicitly.

- **ORM/driver awareness is limited.** Most drivers treat `honey_bun` as an
  unknown OID and either error or fall back to text. For honey columns this
  is fine because no application code should be reading them anyway.

- **Logical replication subscribers need the extension installed.** If you
  replicate a table containing a `honey_bun` column, the subscriber must
  also have the extension. Otherwise it cannot decode incoming rows.

- **`terminate_on_read` only fires from ordinary client backends.** Parallel
  workers and walsenders execute the same type I/O code but are spared the
  SIGTERM, so logical replication keeps flowing on the publisher and parallel
  plans don't deadlock partway through. The alert still fires from those
  paths; only the termination is suppressed. In practice the leader is where
  result-row typoutput runs for a normal `SELECT *`, so the bulk-exfil case
  is covered.

- **The `honey_bun_out` function may be invoked more than once per row.**
  PostgreSQL does not guarantee exactly-once invocation of `typoutput`. Treat
  log entries as "at least one access," not a precise count. Dedup at the
  alert processor using `pid` and the transaction start.

- **Forge-an-alert primitive is closed at three layers.** First, `EXECUTE`
  is revoked from `PUBLIC` on all four I/O functions (and on every
  alias-generated set from `create_honey_bun_alias()`), so direct
  `SELECT honey_bun_out('forged'::honey_bun)` errors with permission
  denied. Second, `USAGE` is revoked from `PUBLIC` on the `honey_bun`
  type (and every alias type), so a non-superuser cannot `CREATE TABLE
  forge (h honey_bun)` to plant their own honey row. Third — and this
  is the load-bearing layer — `honey_bun_in` and `honey_bun_recv`
  perform their own `pg_type_aclcheck` in C, refusing to construct a
  value if the caller lacks `USAGE` on the destination type. PG itself
  does not check function ACLs on typinput dispatch (the path used by
  `'literal'::sometype` casts and by INSERT typecoercion), so without
  this C-level guard a non-superuser could still write
  `SELECT 'forged'::honey_bun;` and let result-row typeoutput dispatch
  fire the trap with attacker-chosen tag. The trap on existing planted
  columns is unaffected: reading a row does not invoke `honey_bun_in`,
  so `USAGE` is not required for legitimate trap fires. Operators who
  want a specific role to be able to plant honey columns or insert into
  honey-bearing tables should `GRANT USAGE ON TYPE honey_bun TO that_role`.

- **Logical replication subscribers need `USAGE` on `honey_bun` (and on
  any alias types being replicated).** The apply worker calls `honey_bun_recv`
  to materialize incoming row values; the C-level USAGE check fires for the
  subscription role just like any other caller. `GRANT USAGE` to the
  subscription role on the subscriber cluster.

- **The log path is resolved once at server start and frozen for the life
  of the postmaster.** `log_directory` is `PGC_SIGHUP`, so without this an
  attacker with `ALTER SYSTEM` could redirect alerts via the resolve
  fallback path even though `sticky_honey_bun.log_path` itself is
  `PGC_POSTMASTER`. Runtime changes to `log_directory` have no effect on
  where alerts are written.

- **The logger opens the alert file with `O_NOFOLLOW`.** If the file at
  the configured path is a symlink (an attacker with parent-directory
  write may have swapped it to redirect alerts), the open fails and the
  event is silently dropped per the project's "broken log path must not
  surface as a SELECT error" rule. The symlink and its target are not
  modified.

- **Cross-version test plumbing**. The Perl test modules renamed between
  PG 14 (`PostgresNode` / `TestLib`) and PG 15 (`PostgreSQL::Test::Cluster` /
  `PostgreSQL::Test::Utils`). `t/lib/SHB.pm` is a small shim that picks the
  available module set, so all `t/*.pl` tests work on PG 14 through 18.

- **The RDS variant's PL/pgSQL bodies are readable** via `pg_proc`. Anyone
  with `pg_read_all_data` (which `rds_superuser` has) can inspect them. This
  is a hard limitation of running in managed Postgres; for tamper resistance
  use the self-hosted variant.
