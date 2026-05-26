#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: trap fires once per row materialized to the client.
#          - SELECT * fires per row.
#          - SELECT honey FROM t fires per row.
#          - WHERE id = N narrows to one row, one alert.
#          - LIMIT 1 fires once.
#          - count(honey) does NOT fire (aggregate, value not materialized).
#          - count(*) over a subquery projecting honey away does NOT fire.
#
# Self-hosted covers more shapes (DISTINCT, ORDER BY, MIN/MAX, GROUP BY)
# because the C variant ships per-alias comparison operators and
# aggregates. The RDS pg_tle path doesn't, so those shapes are not
# tested here.
#
# Synchronization: each shape carries a unique marker in a SQL comment.
# We run all shapes back-to-back, then plant one final sentinel and
# wait for its alert. Sentinel arrival proves the Lambda has processed
# every earlier dispatch. After that, count_alerts per-marker tells
# us how many times each shape fired.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t011');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag = SHB_RDS::unique_tag($st, 'select_shapes');
$run->("INSERT INTO t VALUES (1, '$tag'), (2, '$tag'), (3, '$tag')");

my @cases = (
    {   label    => 'SELECT * fires once per row',
        select   => 'SELECT * FROM t',
        suffix   => 'sel_star',
        expected => 3, },
    {   label    => 'SELECT honey fires once per row',
        select   => 'SELECT honey FROM t',
        suffix   => 'sel_honey',
        expected => 3, },
    {   label    => 'WHERE id = 1 narrows to one row',
        select   => 'SELECT honey FROM t WHERE id = 1',
        suffix   => 'sel_where',
        expected => 1, },
    {   label    => 'LIMIT 1 fires once',
        select   => 'SELECT honey FROM t LIMIT 1',
        suffix   => 'sel_limit',
        expected => 1, },
    {   label    => 'count(honey) does not fire (aggregate)',
        select   => 'SELECT count(honey) FROM t',
        suffix   => 'sel_count_honey',
        expected => 0, },
    {   label    => 'count(*) over projected-away subquery does not fire',
        select   => 'SELECT count(*) FROM (SELECT id FROM t) s',
        suffix   => 'sel_proj_away',
        expected => 0, },
);

# Run all shapes back-to-back; each carries its own marker in a comment.
for my $c (@cases) {
    $c->{marker} = SHB_RDS::unique_tag($st, $c->{suffix});
    my ($rc) = $run->("/* $c->{marker} */ $c->{select}");
    is($rc, 0, "shape runs cleanly: $c->{label}");
}

# Final sentinel — when its alert arrives, every earlier dispatch is
# done. Use a separate table to avoid mixing into the shape counts.
my $sentinel_tag = SHB_RDS::unique_tag($st, 'final_sentinel');
$run->('CREATE TABLE sentinel (id int, honey honey_bun)');
$run->("INSERT INTO sentinel VALUES (1, '$sentinel_tag')");
$run->('SELECT * FROM sentinel');
my $event = $get_event->($sentinel_tag);
ok($event, 'final sentinel arrived (all prior dispatches processed)');

# Small additional buffer for CloudWatch ingestion to settle on the
# last few events that landed concurrently with the sentinel.
sleep 5;

for my $c (@cases) {
    my $got = SHB_RDS::count_alerts($st, $c->{marker}, since => 300);
    is($got, $c->{expected},
        "count: $c->{label} (got $got, expected $c->{expected})");
}

done_testing();
