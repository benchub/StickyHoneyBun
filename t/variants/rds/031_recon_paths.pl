#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: documents what a non-superuser CAN and CANNOT learn from
#          the catalog about planted honey traps. RDS exposes more
#          than self-hosted because pg_tle's PL/pgSQL bodies are
#          visible via pg_proc.prosrc, where the self-hosted C bodies
#          are not. The README documents this as a hard limitation of
#          managed-Postgres TLEs; pinning it as a test makes any future
#          accidental loosening obvious.
#
# Closed paths (assertion: denied):
#   - honey_bun_columns view (REVOKEd from PUBLIC)
#   - sticky_honey_bun.config table (REVOKEd from PUBLIC)
#
# Open recon paths (assertion: readable — acknowledged limitation):
#   - pg_type lists `honey_bun` by name
#   - pg_proc.prosrc lets attackers read the PL/pgSQL implementation
#     of honey_bun_in_rds / honey_bun_out_rds, including any embedded
#     references to the locked-down config table
#   - pg_attribute joined against honey_bun_registry reconstructs the
#     inventory even without honey_bun_columns access

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs_master = SHB_RDS::schema_setup($st, 'shb_t031');

# Plant a couple of honey columns so the recon paths have something
# to discover.
SHB_RDS::psql_run($cs_master, 'CREATE TABLE customers (id int, honey honey_bun)');
SHB_RDS::psql_run($cs_master, 'CREATE TABLE secrets   (id int, honey honey_bun)');

my $cs_app = SHB_RDS::connstr($st,
    user        => 'shbtest_app',
    password    => $st->{app_password},
    search_path => 'shb_t031');
my $as_app = sub { SHB_RDS::psql_run($cs_app, $_[0]) };

# CLOSED: honey_bun_columns view.
SHB_Assertions::assert_inventory_locked_from_role(
    $as_app,
    'recon: honey_bun_columns denied to app role');

# CLOSED: sticky_honey_bun.config table (the config holding
# lambda_arn). PUBLIC has no access; an attacker session cannot read
# the Lambda ARN this way.
{
    my ($rc, undef, $stderr) = $as_app->(
        'SELECT key, value FROM sticky_honey_bun.config');
    isnt($rc, 0, 'recon: sticky_honey_bun.config SELECT denied to app');
    like($stderr, qr/permission denied/i,
        'recon: config table denial is a permission-denied error');
}

# OPEN: pg_type discovery — anyone can see the honey_bun type exists
# and is in the public schema. The name itself is widely documented
# (this README is open-source). Acknowledged limitation.
{
    my ($rc, $out) = $as_app->(
        "SELECT count(*) FROM pg_type WHERE typname = 'honey_bun'");
    is($rc,  0,   'recon: pg_type readable (PUBLIC catalog)');
    is($out, '1', 'recon: honey_bun discoverable by name');
}

# OPEN on RDS, CLOSED on self-hosted: pg_proc.prosrc leaks the
# PL/pgSQL body of the I/O functions. Pin this as observed reality —
# the README documents it as a hard limitation of pg_tle / managed PG.
{
    my ($rc, $out) = $as_app->(
        "SELECT length(prosrc) FROM pg_proc "
      . "WHERE proname = 'honey_bun_out_rds' "
      . "AND prorettype = 'text'::regtype");
    is($rc, 0, 'recon: pg_proc readable for honey_bun_out_rds');
    cmp_ok($out, '>', 100,
        'recon: PL/pgSQL body of honey_bun_out_rds is fully readable '
      . '(RDS-specific: the C variant hides this behind a $libdir symbol)');
}

# OPEN: catalog-based reconstruction of the inventory. An attacker can
# join pg_attribute against sticky_honey_bun.honey_bun_registry (which
# we DID lock down) to reconstruct the column list — BUT only if they
# can read the registry. Verify both halves.
{
    my ($rc, undef, $stderr) = $as_app->(
        'SELECT count(*) FROM sticky_honey_bun.honey_bun_registry');
    isnt($rc, 0,
        'recon: sticky_honey_bun.honey_bun_registry locked down from PUBLIC');
    like($stderr, qr/permission denied/i,
        'recon: registry denial is permission-denied');
}

done_testing();
