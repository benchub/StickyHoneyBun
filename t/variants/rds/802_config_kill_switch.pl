#!/usr/bin/perl
# Variants: rds
# Asserts: the RDS-only config-table kill switch works — deleting the
#          `lambda_arn` row silences the trap (no Lambda invocation),
#          and restoring it resumes alerting. Parallel concern to the
#          self-hosted `sticky_honey_bun.enabled = off` GUC, but the
#          mechanism translates to a row-DELETE / re-INSERT against
#          the locked-down config table.
#
# Test isolation: this test operates on the `db_a` database (separate
# extension installation, separate config table) so disabling here
# doesn't affect alerts produced by the other test files (which use
# the `postgres` db). The END block restores the row even on failure.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t802', db => 'db_a');
my $get_event = SHB_RDS::get_event_fn($st);

# Snapshot the lambda_arn so we can restore it on exit.
my (undef, $saved_arn) = SHB_RDS::psql_run(
    SHB_RDS::connstr($st, db => 'db_a'),
    "SELECT value FROM shb_rds_internal.sticky_honey_bun_rds_config WHERE key = 'lambda_arn'");
chomp $saved_arn;
diag("saved lambda_arn=$saved_arn for restoration");

# ALWAYS restore — even if the test dies / Ctrl-C / asserts fail.
END {
    if (defined $saved_arn && length $saved_arn) {
        my $restore_cs = SHB_RDS::connstr($st, db => 'db_a');
        SHB_RDS::psql_run($restore_cs,
            "INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config(key, value) "
          . "VALUES ('lambda_arn', '$saved_arn') "
          . "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
        diag("restored lambda_arn in db_a");
    }
}

SHB_RDS::psql_run($cs, 'CREATE TABLE t (id int, honey honey_bun)');

# Baseline: with lambda_arn set, the trap fires.
{
    my $tag = SHB_RDS::unique_tag($st, 'killswitch_baseline');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (1, '$tag')");
    SHB_RDS::psql_run($cs, 'SELECT * FROM t WHERE id = 1');
    my $event = $get_event->($tag);
    ok($event, 'baseline: trap fires when lambda_arn is set');
}

# Flip the kill switch: delete lambda_arn from the config table.
{
    my ($rc) = SHB_RDS::psql_run(
        SHB_RDS::connstr($st, db => 'db_a'),
        "DELETE FROM shb_rds_internal.sticky_honey_bun_rds_config WHERE key = 'lambda_arn'");
    is($rc, 0, 'kill switch flipped: DELETE lambda_arn');
}

# After kill: the trap function still runs (no error), but no Lambda
# invocation happens. We verify by inserting + reading with a marker
# and confirming count_alerts returns 0 for that marker.
{
    my $silent_tag = SHB_RDS::unique_tag($st, 'killswitch_silenced');
    my $marker = SHB_RDS::unique_tag($st, 'killswitch_marker');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (2, '$silent_tag')");
    my ($rc) = SHB_RDS::psql_run(
        $cs, "/* $marker */ SELECT * FROM t WHERE id = 2");
    is($rc, 0,
        'SELECT after kill switch still succeeds (trap fails-quiet, '
      . 'never unmasks)');

    # Wait long enough that Lambda would have ingested anything that did
    # fire. The 60s wait is conservative — past test runs show Lambda
    # events appearing well inside this window.
    sleep 60;

    my $count = SHB_RDS::count_alerts($st, $marker, since => 180);
    is($count, 0,
        'kill switch silenced the trap: no Lambda alerts after DELETE');
}

# Restore (the END block will also restore on success, but doing it
# inline lets the next assertion confirm restoration works).
{
    my ($rc) = SHB_RDS::psql_run(
        SHB_RDS::connstr($st, db => 'db_a'),
        "INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config(key, value) "
      . "VALUES ('lambda_arn', '$saved_arn')");
    is($rc, 0, 'kill switch restored: INSERT lambda_arn back');

    my $resume_tag = SHB_RDS::unique_tag($st, 'killswitch_resumed');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (3, '$resume_tag')");
    SHB_RDS::psql_run($cs, 'SELECT * FROM t WHERE id = 3');
    my $event = $get_event->($resume_tag);
    ok($event, 'trap fires again after lambda_arn restored');
}

done_testing();
