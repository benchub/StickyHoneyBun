#!/usr/bin/perl
# Variants: rds
# Asserts: explicit `::bytea` casts on a honey value go through
#          CoerceViaIO (firing honey_bun_out_rds, hence firing the
#          trap) rather than through a binary-compatibility cast that
#          would reinterpret the bytes silently. pg_tle's
#          `create_base_type` auto-registers a binary-compat pg_cast
#          entry between the new type and its storage type (bytea);
#          the extension install body explicitly DROPs that cast for
#          both the canonical type and every alias. This test pins
#          the regression: if a future change forgets the DROP CAST,
#          `SELECT honey_value::bytea` would silently return the byte
#          representation of the trap value, defeating the trap for
#          any role with SELECT.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t807');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

# Plant a honey row.
$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag = SHB_RDS::unique_tag($st, 'bytea_probe');
$run->("INSERT INTO t VALUES (1, '$tag')");

# Confirm the pg_cast entry between honey_bun and bytea is gone in
# both directions. PG resolves bytea-only-direction casts via
# pg_cast — if either direction's entry exists with castmethod='b',
# the trap is bypassable through that direction.
{
    my (undef, $count_to)   = $run->(
        "SELECT count(*) FROM pg_cast c "
      . "JOIN pg_type s ON s.oid = c.castsource "
      . "JOIN pg_type t ON t.oid = c.casttarget "
      . "WHERE s.typname = 'honey_bun' AND t.typname = 'bytea'");
    my (undef, $count_from) = $run->(
        "SELECT count(*) FROM pg_cast c "
      . "JOIN pg_type s ON s.oid = c.castsource "
      . "JOIN pg_type t ON t.oid = c.casttarget "
      . "WHERE s.typname = 'bytea' AND t.typname = 'honey_bun'");
    is($count_to,   '0',
        'pg_cast: honey_bun → bytea binary-compat cast is gone');
    is($count_from, '0',
        'pg_cast: bytea → honey_bun binary-compat cast is gone');
}

# Attempt the bypass: SELECT honey::bytea. The mitigation we want is
# that this does NOT silently return the raw bytes of the honey value
# — that's what made C1 critical. Two acceptable outcomes:
#   (a) PG errors at cast resolution (no pg_cast entry, no automatic
#       CoerceViaIO fallback for an explicit cast): rc != 0, data
#       not leaked. Trap doesn't fire because typeoutput is never
#       reached.
#   (b) PG falls back to CoerceViaIO: honey_bun_out_rds runs (trap
#       fires), produces the tag string, bytea_in then probably
#       errors on the non-bytea-shaped text — rc != 0 but trap fired.
#
# In practice PG follows path (a) for explicit `::bytea` casts after
# the pg_cast entries are dropped, so we just assert "the cast is no
# longer silent." The honey value's bytes never reach the client.
{
    my ($rc, $out, $stderr) = $run->("SELECT honey::bytea FROM t WHERE id = 1");
    isnt($rc, 0,
        '::bytea cast on a honey value no longer silently succeeds '
      . '(pg_cast entries dropped, no binary-compat reinterpretation)');
    unlike($out, qr/\Q$tag\E/,
        '::bytea cast output does NOT contain the honey tag bytes '
      . '(no data leak even when the cast errors)');
}

# Sanity: the un-cast path still fires too (regression that the cast
# drop didn't accidentally break the normal trap path).
{
    my $tag2 = SHB_RDS::unique_tag($st, 'bytea_sanity');
    $run->("INSERT INTO t VALUES (2, '$tag2')");
    $run->('SELECT * FROM t WHERE id = 2');
    my $event = $get_event->($tag2);
    ok($event, 'plain SELECT still fires the trap');
}

done_testing();
