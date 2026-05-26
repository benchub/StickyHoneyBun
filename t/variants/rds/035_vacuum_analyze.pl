#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: ANALYZE and VACUUM on a honey-bearing table do NOT fire the
#          trap. Both commands walk the relation through typcmp / the
#          storage layer; neither invokes typeoutput.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t035');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag = SHB_RDS::unique_tag($st, 'vacuum_probe');
$run->("INSERT INTO t SELECT g, '$tag' FROM generate_series(1, 100) g");

my $marker = SHB_RDS::unique_tag($st, 'vacuum_marker');

# Run the maintenance ops, then drop a sentinel to gate the count
# check. When the sentinel arrives, any alerts the maintenance ops
# WOULD have produced have also been ingested. If $count_alerts then
# returns 0 for the marker, the maintenance ops were silent.
SHB_Assertions::assert_maintenance_ops_silent(
    $run,
    sub {
        my ($needle) = @_;
        # Sentinel: planted last, SELECTed last, polled last. After it
        # arrives, the maintenance window is settled.
        my $sentinel = SHB_RDS::unique_tag($st, 'vacuum_sentinel');
        $run->("INSERT INTO t VALUES (200, '$sentinel')");
        $run->('SELECT * FROM t WHERE id = 200');
        my $event = $get_event->($sentinel);
        ok($event, 'vacuum_analyze: sentinel arrived (count is now consistent)');
        sleep 5;   # small CloudWatch ingest buffer
        return SHB_RDS::count_alerts($st, $needle, since => 180);
    },
    $marker);

done_testing();
