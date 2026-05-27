#!/usr/bin/perl
# Variants: rds
# Asserts: the owner-controlled `enabled` row in the locked-down
#          shb_rds_internal.sticky_honey_bun_rds_config table is a working kill switch.
#          Setting it to 'off' silences the trap; removing the row
#          (or setting it to any non-disable value) resumes alerting.
#          This is the RDS analog of the self-hosted PGC_POSTMASTER
#          `sticky_honey_bun.enabled = off` (t/007). The mechanism
#          differs (table row vs GUC) but the operational property is
#          the same: an attacker session cannot flip it.
#
# Test isolation: operates on the `postgres` database. The END block
# restores the row's prior state even on failure so subsequent tests
# in this run aren't broken.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t806');
my $get_event = SHB_RDS::get_event_fn($st);

my $cs_config = SHB_RDS::connstr($st);   # plain postgres-db connection for config table writes

# Snapshot the prior `enabled` value (if any) and restore it on exit.
my (undef, $saved_enabled) = SHB_RDS::psql_run($cs_config,
    "SELECT coalesce(value, '__missing__') FROM shb_rds_internal.sticky_honey_bun_rds_config WHERE key = 'enabled' "
  . "UNION ALL SELECT '__missing__' LIMIT 1");
chomp $saved_enabled;

END {
    if ($saved_enabled eq '__missing__') {
        SHB_RDS::psql_run($cs_config,
            "DELETE FROM shb_rds_internal.sticky_honey_bun_rds_config WHERE key = 'enabled'");
    } else {
        SHB_RDS::psql_run($cs_config,
            "INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config(key, value) "
          . "VALUES ('enabled', '$saved_enabled') "
          . "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
    }
}

SHB_RDS::psql_run($cs, 'CREATE TABLE t (id int, honey honey_bun)');

# Baseline: with `enabled` absent (default), the trap fires.
{
    my $tag = SHB_RDS::unique_tag($st, 'killswitch_baseline');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (1, '$tag')");
    SHB_RDS::psql_run($cs, 'SELECT * FROM t WHERE id = 1');
    my $event = $get_event->($tag);
    ok($event, 'baseline: trap fires when `enabled` is absent (default behavior)');
}

# Flip the kill switch: set `enabled` to 'off'.
{
    my ($rc) = SHB_RDS::psql_run($cs_config,
        "INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config(key, value) VALUES ('enabled', 'off') "
      . "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
    is($rc, 0, 'kill switch flipped: UPDATE enabled=off');
}

# After kill: SELECT succeeds, no alert is generated.
{
    my $silent_tag = SHB_RDS::unique_tag($st, 'killswitch_silenced');
    my $marker     = SHB_RDS::unique_tag($st, 'killswitch_marker');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (2, '$silent_tag')");
    my ($rc) = SHB_RDS::psql_run($cs,
        "/* $marker */ SELECT * FROM t WHERE id = 2");
    is($rc, 0,
        'SELECT after enabled=off still succeeds (trap fails-quiet)');

    sleep 60;   # let any in-flight Lambda invokes settle
    my $count = SHB_RDS::count_alerts($st, $marker, since => 180);
    is($count, 0,
        'enabled=off silenced the trap: no Lambda alerts');
}

# Flip back: set `enabled` to 'on' (or any non-disable value).
{
    my ($rc) = SHB_RDS::psql_run($cs_config,
        "UPDATE shb_rds_internal.sticky_honey_bun_rds_config SET value = 'on' WHERE key = 'enabled'");
    is($rc, 0, 'kill switch restored: UPDATE enabled=on');

    my $resume_tag = SHB_RDS::unique_tag($st, 'killswitch_resumed');
    SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (3, '$resume_tag')");
    SHB_RDS::psql_run($cs, 'SELECT * FROM t WHERE id = 3');
    my $event = $get_event->($resume_tag);
    ok($event, 'trap fires again after enabled flipped back to on');
}

# Verify the lockdown: an app role cannot flip the switch.
{
    my $cs_app = SHB_RDS::connstr($st,
        user     => 'shbtest_app',
        password => $st->{app_password});
    my ($rc, undef, $stderr) = SHB_RDS::psql_run($cs_app,
        "UPDATE shb_rds_internal.sticky_honey_bun_rds_config SET value = 'off' WHERE key = 'enabled'");
    isnt($rc, 0,
        'app role cannot flip the enabled switch (config table is REVOKEd)');
    like($stderr, qr/permission denied/i,
        'kill-switch tamper attempt is permission-denied');
}

done_testing();
