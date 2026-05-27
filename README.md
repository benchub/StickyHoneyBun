# Sticky Honey Bun

![Sticky Honey Bun](yum.png)

Sticky Honey Bun is a PostgreSQL extension that gives you honey tokens in the form of a custom data type. Simply add a new column to any table(s) you want, put a non-null value into said column for any row(s) that you will never select, and 💥! You now have a trap for an attacker who comes in and does an unwary `SELECT * FROM table`.

Sticky Honey Bun alerts are simple - they just log information about who, what, where, when, etc. It is up to the alert processor to decide if the alert is legit and what action should be taken. Actions can be as simple as sending an email or as complicated as revoking the user access or locking everything down. Regardless, that alert processor lives outside of the DB, and is yours to craft as you desire.

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
| `cluster_id` | RDS variant only, set via the `sticky_honey_bun.config` table (key `cluster_id`) | Identifies the source cluster when one Lambda fans many in |
| `server_addr` | the local address PG was connected to (`MyProcPort->laddr` on self-hosted, `inet_server_addr()` on RDS) | Identifies which node within a cluster fired — primary vs each replica/standby. Always populated, independent of operator-set `cluster_id`. For unix-socket connections (typical in local/test deployments) carries `local:<socket-path>` so two PG instances on the same host stay distinguishable; for TCP connections, the listening IP |

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
SELECT * FROM customers WHERE honey IS NOT NULL;
```

The honey token value is opaque to the extension — it is emitted verbatim
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

While `create_honey_bun_alias` exists in both the self-hosted and RDS variants, the mechanisms differ:

- **Self-hosted (C)**: each alias gets its own SQL-level I/O functions
  bound to the same compiled C symbols, plus a full set of comparison
  operators, btree/hash op classes, and `min`/`max` aggregates so
  `DISTINCT`/`ORDER BY`/`MIN`/`MAX`/`GROUP BY` all work on aliased columns.
- **RDS (pg_tle)**: each alias re-registers the type via
  `pgtle.create_base_type` pointing at the same PL/pgSQL I/O functions.
  A `honey_bun_registry` table tracks which types are honey-shaped so the
  `honey_bun_columns` view can find them.

Aliases trap identically to `honey_bun` and appear in the `honey_bun_columns` inventory view.
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
* `pg_tle` extension (whitelist via `rds.allowed_extensions` /  `aurora.allowed_extensions` parameter group,  then `CREATE EXTENSION pg_tle`).
* `aws_lambda` extension.
* IAM role on the RDS instance with `lambda:InvokeFunction` on the target Lambda (deploy `lambda/handler.py`).

```sh
psql ... -f rds/sticky_honey_bun_rds.sql
psql ... -c "CREATE EXTENSION sticky_honey_bun_rds"

# Configure the Lambda ARN (and optional cluster_id) in the locked-down
# config table. Run as the extension owner — PUBLIC has no access.
psql ... <<SQL
INSERT INTO sticky_honey_bun.config(key, value) VALUES
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

### Schema layout

Sticky Honey Bun ships its non-type internals in a dedicated
`sticky_honey_bun` schema (REVOKEd from PUBLIC) so that a common
production misconfig — `GRANT ... ON ALL TABLES IN SCHEMA public TO
some_role` after install — does NOT silently re-grant access to the
extension's inventory view, alias function, or config:

| Object | Self-hosted | RDS |
|---|---|---|
| `honey_bun` type | `<install_schema>` | `public` (pg_tle constraint) |
| `honey_bun_in` / `_out` / `_recv` / `_send` (or `_in_rds` / `_out_rds`) | `<install_schema>` | `public` (pg_tle constraint) |
| operators / op classes / aggregates | `<install_schema>` | (not provided) |
| `honey_bun_columns` view | `<install_schema>` | `sticky_honey_bun` |
| `create_honey_bun_alias` function | `<install_schema>` | `sticky_honey_bun` |
| `honey_bun_registry` table | (not used) | `sticky_honey_bun` |
| `config` table | (uses GUCs) | `sticky_honey_bun` |

**Self-hosted is relocatable**: `<install_schema>` is whatever you
pass to `CREATE EXTENSION sticky_honey_bun WITH SCHEMA <name>`,
defaulting to your current `search_path`. For production-hardened
installs, use `WITH SCHEMA sticky_honey_bun` (you'll need to
`CREATE SCHEMA sticky_honey_bun` first) or pick any custom name —
useful for masking the trap.

**RDS hardcodes `sticky_honey_bun`** because pg_tle TLE install
bodies aren't parameterizable. Operators who want a different schema
name fork the TLE body (`rds/sticky_honey_bun_rds.sql`) and reinstall
under a new TLE name.

### Configuration (RDS variant)

`pg_tle` in RDS does not allow custom-namespace GUCs to be set
durably. The RDS variant therefore stores its configuration in a
locked-down table inside the `sticky_honey_bun` schema:

```sql
CREATE TABLE sticky_honey_bun.config (
    key   text PRIMARY KEY,
    value text
);
REVOKE ALL ON sticky_honey_bun.config FROM PUBLIC;
```

| Key | Description |
|---|---|
| `lambda_arn` | ARN of the Lambda to invoke on trap events. Required for alerts to fire; absent or empty disables alerting (the trap returns the tag transparently). |
| `cluster_id` | Optional identifier emitted in the payload so a shared Lambda can route by source cluster. |
| `enabled` | Optional owner-controlled kill switch. Absent or anything that isn't one of `off` / `false` / `0` / `no` is treated as enabled. When set to a disable value, the trap returns the tag without firing the Lambda. |

The output function `honey_bun_out_rds` runs `SECURITY DEFINER` and reads
this table as the extension owner. PUBLIC has no `SELECT`, `INSERT`,
`UPDATE`, or `DELETE` on the config table, so an attacker session cannot
read the Lambda ARN, cannot silence the trap by emptying it, cannot
redirect alerts by overwriting it, and cannot flip the `enabled` switch.
Configuration changes go through the extension owner.

The `enabled` switch is the locked-down-table analog of the self-hosted
`sticky_honey_bun.enabled` GUC. To disable the trap an operator can either flip `enabled` (cheap, reversible) or 
`DROP EXTENSION sticky_honey_bun_rds` (more auditable infrastructure
activity).

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

Tests are organized under `t/variants/`, with a sub-directory per
variant (`self-hosted/` and `rds/`) and shared assertion bodies in
`t/lib/SHB_Assertions.pm`. The file-level conventions, the per-concern
**coverage matrix** (which concerns are tested in which variants and
which are intentionally skipped), and the guidance for adding new
tests all live in **[`t/variants/README.md`](t/variants/README.md)**.

Self-hosted suite (uses `PostgreSQL::Test::Cluster`, runs in docker):

```sh
make docker-test-15        # run TAP suite against PG 15
make docker-test-matrix    # run against PG 14, 15, 16, 17, 18
make docker-test-ubsan-15  # PG 15 with UBSAN-instrumented extension
```

RDS suite (provisions a real RDS instance + read replica + Lambda
in your AWS account, costs a few cents per run, tears everything down
at the end):

```sh
make rds-test-online       # see rds/online/README.md for the env contract
```

The harness's cleanup story is in `rds/online/README.md` (tag-based
discovery, refuse-if-tag-mismatch delete, always-fire `END {}` block,
`make rds-list-orphans` safety net).

For ad-hoc validation against a real cluster you already have, the
manual smoke test at `rds/smoke_test.sh` exercises the RDS variant's
install + plant + read path against whatever PG endpoint your env
vars point at.

### TDD discipline

New functionality starts with a failing test under
`t/variants/<variant>/`. Cross-variant assertion bodies go in
`t/lib/SHB_Assertions.pm`. Run `make docker-test-15` for inner-loop
feedback. Tests that don't care about heartbeats should set
`sticky_honey_bun.heartbeat_interval_seconds = 0` in their cluster
config to keep the log file deterministic.

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

- **`pg_repack` does not trip the trap.** The online-repack rewrite path is
  `CREATE TABLE AS` + log-table replay + catalog swap; none of those invoke
  `typoutput`/`typsend`. Recheck when PG 19's built-in `REPACK CONCURRENTLY`
  ships — its implementation uses logical replication under the covers, and
  logical replication on the publisher DOES fire the trap (see above), so
  the built-in concurrent repack may need an alert-processor suppression
  rule the way `pg_dump` does.

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

## Known bypass paths

These are paths a SQL-level attacker can take to read honey-bearing
rows or read-around the trap without firing it. They follow directly
from how PostgreSQL's executor and type system work, and from what
Sticky Honey Bun explicitly *isn't* trying to do (see "Not goals").
They're documented here so an operator can reason about the trap's
real coverage when designing their detection pipeline.

### The trap is column-projection-scoped

The C / pg_tle output functions fire only when the honey value is
**projected to the client**. Any query that touches a honey-bearing
row but never asks PG to materialize the honey column is silent. In
practice this means:

- **Column avoidance**: `SELECT id, email FROM customers` (omitting
  the honey column) reads every non-honey field with zero alerts.
- **WHERE-only access**: `SELECT id FROM customers WHERE id != 5` /
  `LIMIT 4` / CTE/subquery wrappings that project the honey column
  away silently extract every other column. PG applies the WHERE
  quals against raw heap tuples before any output function dispatch.
- **`RETURNING` clauses with honey omitted**:
  `DELETE FROM customers WHERE id = 5 RETURNING id, email, full_name`
  destroys the row, returns its non-honey columns, and never fires
  the trap. Worst case in this category: silent exfil paired with a
  destructive write. The attacker needs DML.
- **`INSERT INTO target SELECT FROM honey_table`**: copies honey
  values from one column to another without ever projecting them to
  a client. The source row's typeoutput is not invoked when the
  destination column is the same type.
- **`EXPLAIN ANALYZE`**: PG's EXPLAIN DestReceiver discards tuples
  without invoking attribute output functions. So `EXPLAIN ANALYZE
  SELECT * FROM customers` scans honey rows but never fires. It also
  exposes row counts and (after autovacuum) planner row estimates
  via `Plan Rows:` / `Rows Removed by Filter:` — a near-perfect
  silent probe.

This is by design: the trap protects column *reads*, not column
*touches*. Closing it would require hooking the executor's per-attribute
dispatch, which an extension cannot do cleanly. **Operators who care
about projection-bypass paths should pair the trap with alert
processor's filtering of writes against honey tables in PG's own
csvlog / pgaudit stream.** The trap detects who *reads* the honey;
the audit log catches who *touches* the row.

### `pg_basebackup` / REPLICATION privilege is SELECT-on-everything without alerts

A role with `REPLICATION` privilege can run `pg_basebackup` and ship
the raw heap to a target directory, bypassing the type system
entirely (`strings base/.../<oid>` recovers honey tag values). The
trap never fires because walsender uses neither `typoutput` nor
`typsend`. README's "Not goals" already excludes OS-level data
theft; REPLICATION is the SQL-level equivalent of that, so it lives
here as the same class of concern. **The defense is at the role-
grants layer: `REPLICATION` is a high-privilege grant; track it
separately and revoke it from any role that doesn't need replication
specifically.**

### Comparison / sort operators on self-hosted bypass typeoutput (RDS does not)

The self-hosted C variant ships `=` / `<` / `cmp` / `hash` / `MIN` /
`MAX` operators bound to PG's built-in `byteaeq` / `byteacmp` /
`hashvarlena` — so `ORDER BY honey`, `MAX(honey)`, `DISTINCT honey`,
and joins on honey columns all work ergonomically. They also all
**bypass the trap** when the honey value isn't projected:
`SELECT id FROM customers ORDER BY last_token DESC LIMIT 1` leaks
the ID of the highest-honey-value row with zero alerts. The RDS
pg_tle variant is strictly stronger here — it doesn't auto-generate
operators, so these queries error out instead. The self-hosted
variant trades ergonomics for silent comparison primitives;
operators who want the RDS-style safety can drop the operators
manually post-install. Closing this in-code would require binding
the operators to wrappers that invoke the trap before delegating —
which fires alerts on every comparison and is noisy.

### Catalog reconstruction defeats `honey_bun_columns` lockdown

The `REVOKE ALL ON honey_bun_columns FROM PUBLIC` is operator-
convenience, not a confidentiality boundary. PostgreSQL's `pg_type`,
`pg_proc`, `pg_attribute`, and (for RDS) `pg_proc.prosrc` are
world-readable by default. An attacker who knows the trap function
name can join those catalogs to reconstruct the full
`(schema, table, column)` map without firing the trap. Self-hosted
aliases all share the same C symbol in `pg_proc.prosrc`
(`honey_bun_out`); RDS aliases each show their per-alias wrapper
whose body contains `honey_bun_out_rds`. Either is a one-query
reconstruction. **Do not rely on the inventory view for opacity;
do rely on it for ergonomics and for keeping casual users from
stumbling onto trap locations.** If you need confidentiality of trap
locations against a determined SQL-level attacker, deploy aliases
liberally and let the catalog enumeration cost more queries.

### `pg_stats` is a quiet side-channel

Even with `pg_statistic` not directly readable as the planner's
table, `pg_stats` (the publicly-readable view over it) exposes
`avg_width`, `null_frac`, and (via `pg_stat_user_indexes`) the names
of partial indexes the operator may have created on honey columns.
An attacker reading `pg_stats` can infer:
- The approximate length of honey tags (`avg_width`).
- The exact count of honey-bearing rows (`null_frac × reltuples`).
- The name of a `WHERE honey IS NOT NULL` partial index, which often
  hints at the column name.
- The `last_analyze` timestamp.

All read with zero alerts. With two or more distinct honey values,
`pg_statistic.stavaluesN` *would* hold the tag values; reading them
through `pg_stats`' `anyarray::text` cast WOULD fire the trap, but
the value is also returned to the attacker before the alert lands —
the detection-vs-leak race favors whoever reads the result first.
**Operators who care about this can `REVOKE SELECT ON pg_statistic
FROM PUBLIC` (PG-version-dependent) or rotate honey columns'
ANALYZE settings.**

### RDS error message names the trap function

On RDS, an unprivileged role that runs `SELECT * FROM honey_table`
gets `ERROR: permission denied for function honey_bun_out_rds`
because pg_tle's wrapper architecture consults function ACLs (PG's
native typeoutput dispatch does not). The error message names the
trap. An attacker iterating column-by-column can map every honey
column with zero alerts AND zero forgery. The self-hosted C variant
does not have this surface — its typeoutput dispatch bypasses ACLs
and fires the trap normally. We don't fix this on RDS because the
alternative (`GRANT EXECUTE` on `honey_bun_out_rds` to PUBLIC)
re-opens the alert-forge primitive, where an attacker calls the
function directly with an arbitrary tag. **Operators who care about
this trade-off on RDS can deploy a self-hosted standby that mirrors
the same tables; that path fires normally.**

### Blanket grants on the public schema can re-expose the RDS config table

If an operator issues `GRANT ALL ON ALL TABLES IN SCHEMA public TO
some_role` *after* installing the RDS extension, that grant overrides
the extension's `REVOKE`. Sticky Honey Bun installs the config table
in a dedicated `sticky_honey_bun` schema (also REVOKEd from PUBLIC)
specifically to avoid this trap. **Do not move the config table back
to `public`; do not grant access to `sticky_honey_bun` to any role
that doesn't need to administer the trap.**

## License

Sticky Honey Bun is released under the PostgreSQL License — the same
permissive license PostgreSQL itself ships under. Full text in `LICENSE`.
