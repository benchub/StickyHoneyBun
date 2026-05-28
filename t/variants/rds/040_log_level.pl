#!/usr/bin/perl
# Variants: rds
# Asserts: the alert_log_level / heartbeat_log_level config keys copy
#          each event into PG's own logging stream at the configured
#          level — letting an operator run the RDS variant with no
#          Lambda at all and consume events from the (already-
#          CloudWatch-exported) PG log stream.
#
# Test isolation: operates on the `db_a` database (separate config
# table from the rest of the suite, which uses `postgres`). DELETEs
# `lambda_arn` during the test so the trap fires WITHOUT invoking
# Lambda; the END block restores everything.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t040', db => 'db_a');
my $cs_config = SHB_RDS::connstr($st, db => 'db_a');

# Connection string that pre-sets client_min_messages=debug5 in the
# psql session so RAISE LOG/NOTICE/WARNING land on stderr we can
# capture. The `search_path` half is already baked in by
# SHB_RDS::connstr; we have to weave the extra `-c` setting into the
# same `options=` URI parameter.
sub cs_with_client_messages {
    my ($state, %opts) = @_;
    my $base = SHB_RDS::connstr($state, %opts);
    # The connstr returned by SHB_RDS::connstr already terminates with
    # `options=-c%20search_path%3D...`. Append another `-c` setting
    # using space-separated form (psql accepts multiple `-c` tokens in
    # `options`).
    $base .= '%20-c%20client_min_messages%3Ddebug5';
    return $base;
}
my $cs_chatty = cs_with_client_messages($st, db => 'db_a',
    search_path => 'shb_t040');

# Snapshot the lambda_arn and any prior level keys for END restore.
my (undef, $saved_arn) = SHB_RDS::psql_run($cs_config,
    "SELECT value FROM sticky_honey_bun.config WHERE key = 'lambda_arn'");
chomp $saved_arn;

END {
    if (defined $saved_arn && length $saved_arn) {
        SHB_RDS::psql_run($cs_config,
            "INSERT INTO sticky_honey_bun.config(key, value) "
          . "VALUES ('lambda_arn', '$saved_arn') "
          . "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
    }
    SHB_RDS::psql_run($cs_config,
        "DELETE FROM sticky_honey_bun.config "
      . "WHERE key IN ('alert_log_level', 'heartbeat_log_level')");
}

SHB_RDS::psql_run($cs, 'CREATE TABLE t (id int, honey honey_bun)');

# --- arrange: drop lambda_arn, set levels ---
{
    my ($rc) = SHB_RDS::psql_run($cs_config,
        "DELETE FROM sticky_honey_bun.config WHERE key = 'lambda_arn'");
    is($rc, 0, 'arrange: lambda_arn deleted (log-stream-only mode)');

    ($rc) = SHB_RDS::psql_run($cs_config,
        "INSERT INTO sticky_honey_bun.config(key, value) VALUES "
      . "('alert_log_level', 'warning'), "
      . "('heartbeat_log_level', 'log') "
      . "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
    is($rc, 0, 'arrange: alert_log_level=warning, heartbeat_log_level=log');
}

# --- alert path: plant + read a non-heartbeat tag ---
{
    my $tag = SHB_RDS::unique_tag($st, 'log_level_alert');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (1, '$tag')");
    my ($rc, undef, $stderr) = SHB_RDS::psql_run($cs_chatty,
        'SELECT * FROM t WHERE id = 1');
    is($rc, 0, 'alert: SELECT succeeds (log-stream sink does not error)');
    like($stderr, qr/WARNING/,
        'alert: RAISEd at WARNING (matches alert_log_level)');
    like($stderr, qr/\Q"tag":"$tag"\E/,
        'alert: log line contains the planted tag');
    like($stderr, qr/"event":"read_text"/,
        'alert: log line contains event=read_text');

    # And: nothing reached the Lambda (because lambda_arn is null).
    sleep 60;
    my $count = SHB_RDS::count_alerts($st, $tag, since => 180);
    is($count, 0,
        'alert: lambda_arn-null path does not invoke Lambda — '
      . 'log stream is the sole sink');
}

# --- heartbeat path: tag starting with the documented prefix ---
{
    my $hb_tag = 'sticky_honey_bun.heartbeat.test_' . $$ . time();
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (2, '$hb_tag')");
    my ($rc, undef, $stderr) = SHB_RDS::psql_run($cs_chatty,
        'SELECT * FROM t WHERE id = 2');
    is($rc, 0, 'heartbeat: SELECT succeeds');
    like($stderr, qr/^LOG:/m,
        'heartbeat: RAISEd at LOG (heartbeat_log_level, NOT alert_log_level)');
    like($stderr, qr/\Q"tag":"$hb_tag"\E/,
        'heartbeat: log line contains the planted tag');
}

# --- regression: levels=off + lambda_arn null = full fail-quiet ---
{
    my ($rc) = SHB_RDS::psql_run($cs_config,
        "DELETE FROM sticky_honey_bun.config "
      . "WHERE key IN ('alert_log_level', 'heartbeat_log_level')");
    is($rc, 0, 'regression arrange: clear both levels');

    my $tag = SHB_RDS::unique_tag($st, 'log_level_silent');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (3, '$tag')");
    (my $select_rc, undef, my $stderr) = SHB_RDS::psql_run($cs_chatty,
        'SELECT * FROM t WHERE id = 3');
    is($select_rc, 0, 'regression: SELECT still succeeds');
    unlike($stderr, qr/\Q$tag\E/,
        'regression: levels off + lambda null = no PG-log output '
      . '(the trap is fully muted)');
}

done_testing();
