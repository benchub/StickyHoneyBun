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
