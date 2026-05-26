#!/usr/bin/perl
# Variants: rds
# Asserts: direct calls to honey_bun_out_rds are REVOKEd from PUBLIC.
#          A non-privileged role calling the function by name (rather
#          than going through typeoutput dispatch on a stored value)
#          gets permission-denied.

use strict;
use warnings;
use lib 'rds/online/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();

# App role has no EXECUTE on honey_bun_out_rds, so calling it directly
# must fail. Without this REVOKE an attacker could probe the function
# (and discover the Lambda ARN by reading pg_proc), so this assertion
# is part of the lockdown contract documented in README's "Configuration
# (RDS variant)" section.
my $cs = SHB_RDS::connstr($st,
    user     => 'shbtest_app',
    password => $st->{app_password});

my ($rc, $out, $err) = SHB_RDS::psql_run(
    $cs, "SELECT honey_bun_out_rds(convert_to('forged','UTF8'))");

isnt($rc, 0, 'direct call to honey_bun_out_rds is blocked');
like($err, qr/permission denied/i,
    'honey_bun_out_rds blocked with permission denied');

done_testing();
