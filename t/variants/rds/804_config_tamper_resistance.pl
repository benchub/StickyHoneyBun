#!/usr/bin/perl
# Variants: rds
# Asserts: the sticky_honey_bun_rds_config table is tamper-resistant
#          from app-level sessions. The trap function reads it via
#          SECURITY DEFINER (as the extension owner), so the trap
#          path continues to work even though PUBLIC has no access
#          to the table.
#
# This is the RDS analog of the self-hosted `log_path frozen` /
# `enabled = postmaster-only` protections — the locked-down config
# table is what stands between an attacker session and the ability
# to silence or redirect the trap.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs_master = SHB_RDS::schema_setup($st, 'shb_t804');
my $get_event = SHB_RDS::get_event_fn($st);

my $cs_app = SHB_RDS::connstr($st,
    user        => 'shbtest_app',
    password    => $st->{app_password},
    search_path => 'shb_t804');
my $as_app = sub { SHB_RDS::psql_run($cs_app, $_[0]) };

# App role cannot SELECT — can't even discover the Lambda ARN.
{
    my ($rc, undef, $stderr) = $as_app->(
        'SELECT value FROM sticky_honey_bun_rds_config WHERE key = \'lambda_arn\'');
    isnt($rc, 0, 'app cannot SELECT from sticky_honey_bun_rds_config');
    like($stderr, qr/permission denied/i,
        'SELECT denied with permission-denied error');
}

# App role cannot UPDATE — can't redirect alerts to a different Lambda
# or silence them via empty string.
{
    my ($rc, undef, $stderr) = $as_app->(
        "UPDATE sticky_honey_bun_rds_config "
      . "SET value = 'arn:aws:lambda:us-east-1:000000000000:function:hijack' "
      . "WHERE key = 'lambda_arn'");
    isnt($rc, 0, 'app cannot UPDATE sticky_honey_bun_rds_config');
    like($stderr, qr/permission denied/i,
        'UPDATE denied with permission-denied error');
}

# App role cannot DELETE — can't silence by removing the row.
{
    my ($rc, undef, $stderr) = $as_app->(
        "DELETE FROM sticky_honey_bun_rds_config WHERE key = 'lambda_arn'");
    isnt($rc, 0, 'app cannot DELETE FROM sticky_honey_bun_rds_config');
    like($stderr, qr/permission denied/i,
        'DELETE denied with permission-denied error');
}

# App role cannot INSERT — can't add a 'lambda_arn' entry pointing
# elsewhere if one was somehow deleted.
{
    my ($rc, undef, $stderr) = $as_app->(
        "INSERT INTO sticky_honey_bun_rds_config(key, value) "
      . "VALUES ('lambda_arn', 'arn:aws:lambda:us-east-1:0:function:x')");
    isnt($rc, 0, 'app cannot INSERT into sticky_honey_bun_rds_config');
    like($stderr, qr/permission denied/i,
        'INSERT denied with permission-denied error');
}

# Critical regression: the trap path STILL WORKS for app-role reads.
# honey_bun_out_rds is SECURITY DEFINER, so it can read the config
# table as the extension owner regardless of the caller's permissions.
{
    SHB_RDS::psql_run($cs_master,
        'CREATE TABLE t (id int, honey honey_bun)');
    my $tag = SHB_RDS::unique_tag($st, 'tamper_legitimate');
    SHB_RDS::psql_run($cs_master, "INSERT INTO t VALUES (1, '$tag')");
    SHB_RDS::psql_run($cs_master, 'GRANT SELECT ON t TO shbtest_app');
    SHB_RDS::psql_run($cs_master,
        'GRANT USAGE ON SCHEMA shb_t804 TO shbtest_app');

    my ($rc) = $as_app->('SELECT * FROM t');
    is($rc, 0, 'app SELECT on a planted row succeeds (USAGE not required for reads)');

    my $event = $get_event->($tag);
    ok($event,
        'trap fires for app-role read despite app having no access to config table '
      . '(SECURITY DEFINER bridges the gap)');
}

done_testing();
