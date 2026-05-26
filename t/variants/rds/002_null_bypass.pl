#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: reading rows whose honey column is NULL produces no Lambda
#          invocation. Both variants mark the typeoutput function STRICT,
#          which guarantees PG skips it entirely for NULL inputs.
#
# Test strategy on RDS: plant N NULL rows + 1 sentinel, SELECT all with
# a unique marker in a SQL comment, wait for the sentinel alert (proves
# the SELECT executed and Lambda is processing), then count CloudWatch
# events whose `query` field contains the marker. The marker appears
# once per typoutput invocation. Expected count: 1 (sentinel only).
# If NULL bypass failed, count would be 4 (sentinel + 3 NULL alerts
# with tag=null).

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t002');
my $get_event = SHB_RDS::get_event_fn($st);

my $sentinel_tag = SHB_RDS::unique_tag($st, 'null_sentinel');
my $marker       = SHB_RDS::unique_tag($st, 'null_marker');

SHB_RDS::psql_run($cs, 'CREATE TABLE t (id int, honey honey_bun)');
SHB_RDS::psql_run($cs,
    'INSERT INTO t VALUES (1, NULL), (2, NULL), (3, NULL)');
SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (4, '$sentinel_tag')");

# The marker rides along in the SQL comment so it appears in the alert's
# `query` field for every typeoutput invocation produced by this SELECT.
my ($rc) = SHB_RDS::psql_run($cs, "SELECT * FROM t /* $marker */");
is($rc, 0, 'SELECT of NULL-mixed rows succeeds');

# Wait for the sentinel: when it arrives, any null-bypass-failure alerts
# would have been ingested too. This gates the count check below — we
# never count before the Lambda has had time to process this SELECT.
my $event = $get_event->($sentinel_tag);
ok($event, 'sentinel trap fired (proves SELECT executed and Lambda is up)');

# Count alerts whose payload contains our marker. If NULL bypass works,
# the count is exactly 1 (the sentinel's query carries the marker, NULL
# rows did not invoke the function at all). If bypass failed, we'd see
# 4 (one per row).
my $count = SHB_RDS::count_alerts($st, $marker, since => 120);
is($count, 1,
    'exactly one alert produced by SELECT — NULL rows did not fire the trap');

done_testing();
