#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: honey_bun_columns view is REVOKEd from PUBLIC; non-privileged
#          roles cannot enumerate planted traps; an explicit GRANT to
#          a dedicated audit role restores access. The shared assertion
#          is `assert_inventory_locked_from_role` in
#          t/lib/SHB_Assertions.pm.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs_master = SHB_RDS::schema_setup($st, 'shb_t013');

# Plant a honey column so the inventory has something to list.
SHB_RDS::psql_run($cs_master,
    'CREATE TABLE t (id int, honey honey_bun)');

# Master (extension owner) can read the inventory.
{
    my ($rc, $out) = SHB_RDS::psql_run($cs_master,
        'SELECT count(*) FROM honey_bun_columns');
    is($rc, 0, 'master can SELECT honey_bun_columns');
    cmp_ok($out, '>=', '1',
        'master sees at least one planted column');
}

# App role cannot read the inventory (no GRANT).
{
    my $cs_app = SHB_RDS::connstr($st,
        user        => 'shbtest_app',
        password    => $st->{app_password},
        search_path => 'shb_t013');
    SHB_Assertions::assert_inventory_locked_from_role(
        sub { SHB_RDS::psql_run($cs_app, $_[0]) },
        'app role denied honey_bun_columns access');
}

# Grant the audit role access and verify it works.
{
    # Use the deployer role as the audit role for this test — it's the
    # role the harness gives elevated privileges to (USAGE + EXECUTE on
    # the type), so an additional GRANT on the inventory view is a
    # realistic scenario.
    SHB_RDS::psql_run($cs_master,
        'GRANT SELECT ON honey_bun_columns TO shbtest_deployer');
    my $cs_deployer = SHB_RDS::connstr($st,
        user        => 'shbtest_deployer',
        password    => $st->{deployer_password},
        search_path => 'shb_t013');
    my ($rc, $out) = SHB_RDS::psql_run($cs_deployer,
        'SELECT count(*) FROM honey_bun_columns');
    is($rc, 0,
        'deployer (audit role surrogate) with GRANT SELECT can read inventory');
    cmp_ok($out, '>=', '1',
        'deployer sees at least one planted column');
}

done_testing();
