#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts (RDS subset of the red-team playbook): the attack surface
# closed in the self-hosted variant is also closed here, where the
# mechanism translates. Vectors that target self-hosted-only surfaces
# (PGC_POSTMASTER GUCs, log_directory, ALTER SYSTEM) are not
# applicable to RDS and are not tested.
#
# Covered:
#   1. Direct call to honey_bun_in_rds / honey_bun_out_rds — denied.
#   2. Cast 'forged'::honey_bun by a non-USAGE role — denied.
#   3. CREATE TABLE with honey_bun column by a non-USAGE role — denied.
#   4. SELECT * FROM honey_bun_columns by an unprivileged role — denied.
#   5. After all attacks are repelled, a legitimate SELECT on a planted
#      row by an app role with SELECT GRANT still fires the trap.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs_master = SHB_RDS::schema_setup($st, 'shb_t027');

my $cs_app = SHB_RDS::connstr($st,
    user        => 'shbtest_app',
    password    => $st->{app_password},
    search_path => 'shb_t027');
my $as_app = sub { SHB_RDS::psql_run($cs_app, $_[0]) };

# Vector 1: direct I/O function calls.
SHB_Assertions::assert_io_function_call_denied(
    $as_app,
    "SELECT honey_bun_in_rds('forged')",
    'red-team: direct honey_bun_in_rds call');
SHB_Assertions::assert_io_function_call_denied(
    $as_app,
    "SELECT honey_bun_out_rds(convert_to('forged','UTF8'))",
    'red-team: direct honey_bun_out_rds call');

# Vector 2: cast to honey_bun by non-USAGE role.
SHB_Assertions::assert_cast_to_type_denied(
    $as_app, 'honey_bun',
    'red-team: app cast to honey_bun');

# Vector 3: CREATE TABLE with honey_bun column.
# Schema where the app role might plausibly own write access — give it
# CREATE on shb_t027 first to isolate the failure to the type-USAGE
# check (not just a schema-level denial).
SHB_RDS::psql_run($cs_master,
    'GRANT CREATE ON SCHEMA shb_t027 TO shbtest_app');
SHB_Assertions::assert_create_column_of_type_denied(
    $as_app, 'shb_t027', 'honey_bun',
    'red-team: app CREATE TABLE forge (h honey_bun)');

# Vector 4: enumerate planted columns via the inventory view.
SHB_Assertions::assert_inventory_locked_from_role(
    $as_app,
    'red-team: app SELECT * FROM honey_bun_columns');

# Regression: with every defense in place, a legitimate read by an app
# role that the operator has granted SELECT on a honey-bearing table
# MUST still fire the trap. This is the load-bearing positive case —
# if it ever stops firing, the trap is broken.
{
    SHB_RDS::psql_run($cs_master,
        'CREATE TABLE t (id int, honey honey_bun)');
    my $tag = SHB_RDS::unique_tag($st, 'red_team_legitimate');
    SHB_RDS::psql_run($cs_master, "INSERT INTO t VALUES (1, '$tag')");
    SHB_RDS::psql_run($cs_master, 'GRANT SELECT ON t TO shbtest_app');
    SHB_RDS::psql_run($cs_master,
        'GRANT USAGE ON SCHEMA shb_t027 TO shbtest_app');

    my ($rc) = $as_app->('SELECT * FROM t');
    is($rc, 0, 'app role with SELECT can read the planted row');

    my $get_event = SHB_RDS::get_event_fn($st);
    my $event = $get_event->($tag);
    ok($event,
        'legitimate read still fires the trap after every attack vector closed');
    is($event->{tag}, $tag, 'legitimate alert carries the planted tag')
        if $event;
}

done_testing();
