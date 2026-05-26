#!/usr/bin/perl
# Variants: rds
# Asserts: per-database `cluster_id` configuration is independent.
#          A trap in db_a emits cluster_id='shbtest-<run>-a'; a trap in
#          db_b emits cluster_id='shbtest-<run>-b'. Together this is the
#          end-to-end evidence that the locked-down config table is the
#          source of truth (a single Lambda routing payloads by source
#          cluster).
#
# RDS-only concern (the self-hosted variant uses GUC-based config and
# tests that path under t/<future>_cluster_id.pl).

use strict;
use warnings;
use lib 'rds/online/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();

for my $case ([ 'db_a', 'a', $st->{cluster_id_a} ],
              [ 'db_b', 'b', $st->{cluster_id_b} ]) {
    my ($db, $label, $expected_cluster) = @$case;
    my $cs  = SHB_RDS::schema_setup($st, 'shb_t801', db => $db);
    my $tag = SHB_RDS::unique_tag($st, "cluster_$label");

    my ($rc) = SHB_RDS::psql_run($cs,
        'CREATE TABLE t (id int, honey honey_bun); '
      . "INSERT INTO t VALUES (1, '$tag'); "
      . 'SELECT * FROM t');
    is($rc, 0, "trap fires in $db");

    my ($ok, $payload, $err) = SHB_RDS::poll_alert($st, $tag);
    ok($ok, "Lambda received the alert from $db")
        or diag("poll_alert stderr: $err");
    if ($ok) {
        like($payload, qr/\Q$expected_cluster\E/,
            "Lambda payload from $db carries cluster_id=$expected_cluster");
    }
}

done_testing();
