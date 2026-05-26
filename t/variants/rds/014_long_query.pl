#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: a SELECT whose query string is large (~16 KB) still produces
#          exactly one valid alert with the tag intact and the query
#          field preserved. Lambda's async ("Event") invocation payload
#          limit is 256 KB, so 16 KB queries fit comfortably; we still
#          assert the upper bound holds.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t014');
my $get_event = SHB_RDS::get_event_fn($st);

my $tag = SHB_RDS::unique_tag($st, 'long_query');
SHB_RDS::psql_run($cs, 'CREATE TABLE t (id int, honey honey_bun)');
SHB_RDS::psql_run($cs, "INSERT INTO t VALUES (1, '$tag')");

# ~16 KB of padding inside a comment. The comment rides along in
# current_query() and lands verbatim in the alert's `query` field.
my $padding = 'x' x 16000;
my $trigger = "SELECT * FROM t WHERE id = 1 /* $padding */";

SHB_Assertions::assert_alert_fields(
    sub { SHB_RDS::psql_run($cs, $_[0]) },
    $get_event,
    tag     => $tag,
    trigger => $trigger,
    like    => { query => qr/x{16000}/ },
    label   => 'long query (16 KB padding) round-trips through Lambda');

done_testing();
