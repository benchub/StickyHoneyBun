#!/usr/bin/perl
# Variants: rds
# Asserts: planting a honey row and SELECTing it back fires the trap.
#          Lambda invocation reaches CloudWatch (end-to-end evidence).

use strict;
use warnings;
use lib 'rds/online/lib';
use Test::More;
use SHB_RDS;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t003');
my $tag = SHB_RDS::unique_tag($st, 'text_trip');

# Plant + read. The CREATE/INSERT/SELECT body is the textbook trap
# trigger: a master-role session creates a honey-bearing table, inserts
# a tagged row, and reads it back. The SELECT is what causes typoutput
# (and therefore aws_lambda.invoke) to fire on the stored bytea.
{
    my ($rc) = SHB_RDS::psql_run($cs,
        'CREATE TABLE t (id int, honey honey_bun)');
    is($rc, 0, 'master creates honey-bearing table');

    ($rc) = SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (1, '$tag')");
    is($rc, 0, 'master plants honey row');

    ($rc) = SHB_RDS::psql_run($cs, 'SELECT * FROM t');
    is($rc, 0, 'master SELECT * FROM t succeeds (trap fires async)');
}

# End-to-end Lambda evidence. The SELECT above invoked aws_lambda.invoke
# fire-and-forget; CloudWatch ingest lag on a cold Lambda can run 30-90s
# end-to-end, so poll_alert waits up to 240s by default.
{
    my ($ok, $payload, $err) = SHB_RDS::poll_alert($st, $tag);
    ok($ok, "Lambda received the alert for $tag")
        or diag("poll_alert stderr: $err");
}

done_testing();
