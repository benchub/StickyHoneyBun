use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Bgworker liveness regression guard. The heartbeat bgworker is the deadman
# the alert processor uses to distinguish "trap silent because nothing's
# happening" from "trap silent because the logger is broken." This test
# pins down that the worker registers, starts, and emits heartbeats at
# the configured interval.
#
# We deliberately don't query `pg_stat_activity`: after the bgworker was
# refactored to drop BGWORKER_BACKEND_DATABASE_CONNECTION (so it survives
# `DROP DATABASE postgres` — see t/033), the worker is a SHMEM-only
# auxiliary process and no longer appears in `pg_stat_activity`. Heartbeat
# emission is the only externally observable liveness signal — which is
# exactly what the deadman watches.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('bgworker_resilience');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 1
});
$node->start;

sub count_heartbeats {
    return 0 unless -e $log_path;
    open(my $fh, '<', $log_path) or return 0;
    my @lines = <$fh>;
    close $fh;
    return scalar grep { /"event":"heartbeat"/ } @lines;
}

# Worker should be running and emitting heartbeats within a few seconds
# of cluster start.
SHB::wait_until(sub { count_heartbeats() >= 2 }, 10);
cmp_ok(count_heartbeats(), '>=', 2,
    'bgworker emits multiple heartbeats at interval=1s');

# Heartbeats keep flowing over time (not just one burst at startup).
my $before = count_heartbeats();
SHB::wait_until(sub { count_heartbeats() > $before }, 5);
cmp_ok(count_heartbeats(), '>', $before,
    'heartbeat stream continues after the first batch');

$node->stop;
done_testing();
