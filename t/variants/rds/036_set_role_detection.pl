#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: when a session does `SET ROLE` before firing the trap, the
#          alert payload carries:
#            session_user = the authenticated identity (immune to
#                           SET ROLE)
#            current_user = the role-switched identity
#          The alert processor relies on this pair to detect role-switching
#          shenanigans — `session_user != current_user` is a red flag.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t036');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

# Plant a honey row as the master, then grant the deployer role enough
# to perform the SELECT. We use deployer (already configured by setup
# with USAGE + EXECUTE) as the SET ROLE target.
$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag = SHB_RDS::unique_tag($st, 'set_role');
$run->("INSERT INTO t VALUES (1, '$tag')");
$run->('GRANT SELECT ON t TO shbtest_deployer');
$run->('GRANT USAGE ON SCHEMA shb_t036 TO shbtest_deployer');

SHB_Assertions::assert_set_role_reflected_in_alert(
    $run, $get_event,
    tag                   => $tag,
    trigger               => 'SET ROLE shbtest_deployer; SELECT * FROM t',
    expected_session_user => $st->{master_user},
    expected_current_user => 'shbtest_deployer',
    label                 => 'master session pivots to deployer via SET ROLE');

done_testing();
