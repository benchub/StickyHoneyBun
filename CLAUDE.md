# Sticky Honey Bun — working agreements

 ## Test-driven development
- Every new feature starts with a failing TAP test in `t/variants/<variant>/`.
  Cross-variant assertion bodies live in `t/lib/SHB_Assertions.pm`; per-variant
  setup logic lives in `t/lib/SHB.pm` (self-hosted) / `t/lib/SHB_RDS.pm` (rds).
- Do not write or modify implementation code in `src/` or `sql/` without a test that exercises the change first.
- Run `make installcheck` (or `make docker-test-15` for the self-hosted variant;
  `make rds-test-online` for the RDS variant) before declaring work complete.

## Documentation
- Keep `README.md` (and any in-tree docs) in sync with every behavior change: new GUCs, new event types in the log line, new SQL surface, new build targets, supported PG versions.
- When adding a GUC, document: name, default, allowed range, context (USERSET/SIGHUP/POSTMASTER), and what it affects.
- When the log line schema changes, document the JSON field and update any example output.

## Scope discipline
- One feature per change. Don't bundle refactors, doc updates beyond the touched surface, or speculative abstractions.
- Don't add backwards-compat shims for code that hasn't shipped yet.
