#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: direct calls to the RDS I/O function (honey_bun_out_rds) are
#          REVOKEd from PUBLIC — the cross-variant body lives in
#          t/lib/SHB_Assertions.pm and also runs against the C variant's
#          honey_bun_out / honey_bun_send from t/018_io_function_acl.pl.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();

# App role has no EXECUTE on honey_bun_out_rds, so calling it directly
# must fail. Without this REVOKE an attacker could probe the function
# (and discover the Lambda ARN by reading pg_proc), so this assertion
# is part of the lockdown contract documented in README's "Configuration
# (RDS variant)" section.
my $cs_app = SHB_RDS::connstr($st,
    user     => 'shbtest_app',
    password => $st->{app_password});

SHB_Assertions::assert_io_function_call_denied(
    sub { SHB_RDS::psql_run($cs_app, $_[0]) },
    "SELECT honey_bun_out_rds(convert_to('forged','UTF8'))",
    'app-role direct call to honey_bun_out_rds');

done_testing();
