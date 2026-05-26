#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts (RDS-specific behavior): pg_tle base types do not ship a
# binary output function (typsend). Consequences:
#   - COPY ... TO STDOUT BINARY against a honey-bearing table errors
#     with "no binary output function available for type honey_bun"
#     instead of dispatching through a trap.
#   - The trap does NOT fire on the binary path because PG errors
#     before any I/O function runs.
#
# Operator-facing implication: on RDS, a sufficiently sophisticated
# attacker who tries `COPY t TO STDOUT BINARY` discovers via the error
# message that the column has a "special" type. The self-hosted C
# variant covers this path with honey_bun_send and fires the trap
# normally (see t/variants/self-hosted/004_binary_trip.pl).

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t004');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag    = SHB_RDS::unique_tag($st, 'binary_trip');
my $marker = SHB_RDS::unique_tag($st, 'binary_marker');
$run->("INSERT INTO t VALUES (1, '$tag')");

# COPY TO STDOUT BINARY: expected to fail with the specific error.
my ($rc, undef, $stderr) = $run->(
    "/* $marker */ COPY (SELECT honey FROM t) TO STDOUT BINARY");
isnt($rc, 0, 'COPY TO STDOUT BINARY rejected (pg_tle has no typsend)');
like($stderr, qr/no binary output function available for type honey_bun/i,
    'rejection mentions the specific type and missing binary function');

# Sentinel SELECT to gate the count check.
my $sentinel_tag = SHB_RDS::unique_tag($st, 'binary_sentinel');
$run->("INSERT INTO t VALUES (2, '$sentinel_tag')");
$run->('SELECT * FROM t WHERE id = 2');
my $event = $get_event->($sentinel_tag);
ok($event, 'sentinel fired (proves Lambda is up and processing)');

# After the sentinel arrives, anything from the failed COPY would have
# arrived too. The marker should be in zero alerts — the COPY errored
# before the trap could fire.
my $count = SHB_RDS::count_alerts($st, $marker, since => 180);
is($count, 0,
    'failed COPY BINARY produced zero alerts (trap never invoked)');

done_testing();
