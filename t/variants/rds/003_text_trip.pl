#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: planting a honey row and SELECTing it back fires the trap.
#          Cross-variant body in t/lib/SHB_Assertions.pm checks the
#          alert JSON shape (event/tag/pid/ts/session_user). Evidence
#          channel here is Lambda + CloudWatch; the self-hosted twin
#          (t/003_text_trip.pl) reads its local log file.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t003');
my $tag = SHB_RDS::unique_tag($st, 'text_trip');

# poll_alert returns ($ok, $payload, $stderr). The shared assertion
# expects a function that returns the alert text or '' on miss, so
# project to the payload (which on success contains the full Lambda
# log line with the JSON object the C variant writes to disk).
my $get_alert = sub {
    my ($needle) = @_;
    my ($ok, $payload) = SHB_RDS::poll_alert($st, $needle);
    return $ok ? $payload : '';
};

SHB_Assertions::assert_text_trip(
    sub { SHB_RDS::psql_run($cs, $_[0]) },
    $get_alert,
    $tag,
    label => 'RDS honey row text-trip');

done_testing();
