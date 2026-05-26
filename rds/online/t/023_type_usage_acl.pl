#!/usr/bin/perl
# Variants: rds
# Asserts: USAGE on honey_bun gates planting but not reading.
#          - Deployer (USAGE + EXECUTE granted) can cast to honey_bun.
#          - App role (no USAGE) cannot cast.
#          - App role with SELECT on a honey-bearing table still reads
#            successfully and the read fires the trap.

use strict;
use warnings;
use lib 'rds/online/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs_master = SHB_RDS::schema_setup($st, 'shb_t023');

# Deployer can plant: the harness explicitly grants USAGE on the type
# and EXECUTE on the I/O functions to the deployer role. A successful
# cast proves both grants are in place.
{
    my $cs = SHB_RDS::connstr($st,
        user        => 'shbtest_deployer',
        password    => $st->{deployer_password},
        search_path => 'shb_t023');
    my $tag = SHB_RDS::unique_tag($st, 'deployer');
    my ($rc, $out, $err) = SHB_RDS::psql_run(
        $cs, "SELECT '$tag'::honey_bun IS NOT NULL");
    is($rc, 0, 'deployer with USAGE+EXECUTE can cast to honey_bun')
        or diag("deployer cast stderr: $err");
}

# App role cannot plant: REVOKE USAGE FROM PUBLIC means a role without
# an explicit grant can't construct honey_bun values. The has_type_
# privilege check inside honey_bun_in_rds enforces this even though
# pg_tle's typinput dispatch path bypasses function ACLs.
{
    my $cs = SHB_RDS::connstr($st,
        user        => 'shbtest_app',
        password    => $st->{app_password},
        search_path => 'shb_t023');
    my $tag = SHB_RDS::unique_tag($st, 'appcast');
    my ($rc, $out, $err) = SHB_RDS::psql_run(
        $cs, "SELECT '$tag'::honey_bun IS NOT NULL");
    isnt($rc, 0, 'app role cannot cast to honey_bun');
    like($err, qr/permission denied/i,
        'app role cast fails with permission denied');
}

# App role CAN read existing honey-bearing tables — typeoutput dispatch
# doesn't require USAGE on the type, only SELECT on the table. This is
# the load-bearing assertion that the trap fires for the role we're
# actually worried about (an attacker who landed in an app session).
{
    # Master plants the row + grants SELECT.
    SHB_RDS::psql_run($cs_master,
        'CREATE TABLE t (id int, honey honey_bun)');
    my $tag = SHB_RDS::unique_tag($st, 'appread');
    SHB_RDS::psql_run($cs_master, "INSERT INTO t VALUES (1, '$tag')");
    SHB_RDS::psql_run($cs_master, 'GRANT SELECT ON t TO shbtest_app');
    SHB_RDS::psql_run($cs_master,
        'GRANT USAGE ON SCHEMA shb_t023 TO shbtest_app');

    my $cs_app = SHB_RDS::connstr($st,
        user        => 'shbtest_app',
        password    => $st->{app_password},
        search_path => 'shb_t023');
    my ($rc) = SHB_RDS::psql_run($cs_app, 'SELECT * FROM t');
    is($rc, 0, 'app role can SELECT from existing honey-bearing table');

    my ($ok, $payload, $err) = SHB_RDS::poll_alert($st, $tag);
    ok($ok, 'app-role read fires the trap (no USAGE needed for reads)')
        or diag("poll_alert stderr: $err");
}

done_testing();
