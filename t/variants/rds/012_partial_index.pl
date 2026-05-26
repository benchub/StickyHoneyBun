#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: a partial index whose predicate references the honey column
#          (`WHERE honey IS NOT NULL`) does NOT fire the trap during
#          build or analyze. After the index exists, an indexed SELECT
#          that materializes the value DOES fire.
#
# Note: the self-hosted variant indexes the column itself (`ON t (honey)`)
# because the C extension installs a btree opclass for `honey_bun`.
# The RDS pg_tle variant does not ship operator classes, so we index a
# scalar column (`ON t (id)`) with the honey predicate. The interesting
# regression — "evaluating the predicate doesn't fire the trap" — is
# the same in both variants.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t012');
my $get_event = SHB_RDS::get_event_fn($st);

my $marker_build = SHB_RDS::unique_tag($st, 'idx_build_marker');
my $marker_read  = SHB_RDS::unique_tag($st, 'idx_read_marker');
my $tag          = SHB_RDS::unique_tag($st, 'idx_probe');

SHB_RDS::psql_run($cs, 'CREATE TABLE t (id int, honey honey_bun)');
SHB_RDS::psql_run($cs,
    "INSERT INTO t SELECT g, CASE WHEN g = 50 THEN '$tag'::honey_bun "
  . "ELSE NULL END FROM generate_series(1, 100) g");

# Index build phase — the CREATE INDEX statement carries a marker we
# can grep for. If index builds invoked typeoutput, we'd see alerts
# containing that marker. Expected: zero.
my ($rc) = SHB_RDS::psql_run($cs,
    "/* $marker_build */ CREATE INDEX shb_part_idx ON t (id) "
  . 'WHERE honey IS NOT NULL');
is($rc, 0, 'CREATE INDEX succeeds');

($rc) = SHB_RDS::psql_run($cs, "/* $marker_build */ ANALYZE t");
is($rc, 0, 'ANALYZE succeeds');

# Indexed read phase — separate marker so we can distinguish from build.
($rc) = SHB_RDS::psql_run($cs,
    "/* $marker_read */ SELECT honey FROM t WHERE honey IS NOT NULL");
is($rc, 0, 'indexed SELECT succeeds');

# Read alerts must arrive. Wait for the one tagged alert.
my $event = $get_event->($tag);
ok($event, 'indexed read on honey-bearing rows fires the trap');

# Index-build alerts must be zero. Read-phase alerts must be one
# (the single non-NULL row).
my $build_count = SHB_RDS::count_alerts($st, $marker_build, since => 180);
is($build_count, 0,
    'index build produced zero alerts (typcmp path, not typeoutput)');

my $read_count = SHB_RDS::count_alerts($st, $marker_read, since => 180);
is($read_count, 1,
    'indexed SELECT produced exactly one alert (the single non-NULL row)');

done_testing();
