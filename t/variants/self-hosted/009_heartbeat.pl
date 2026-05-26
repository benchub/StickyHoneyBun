use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# sticky_honey_bun.heartbeat_interval_seconds is PGC_POSTMASTER: it can only
# be set in postgresql.conf at server start, so a compromised superuser
# cannot silence the heartbeat (and thereby trigger the alert processor's deadman)
# via ALTER SYSTEM. We test the on path here; the off path is by configuration.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('heartbeat');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 1
});
$node->start;

# Heartbeat runs without CREATE EXTENSION because the .so is preloaded and
# the worker only does OS-level file I/O.

sub count_heartbeats {
    return 0 unless -e $log_path;
    open(my $fh, '<', $log_path) or return 0;
    my @lines = <$fh>;
    close $fh;
    return scalar grep { /"event":"heartbeat"/ } @lines;
}

# Poll up to 10s for the first 2 heartbeats. Sleep-based assertions flake
# on slow CI; polling is robust.
SHB::wait_until(sub { count_heartbeats() >= 2 });
ok(-e $log_path && -s $log_path, 'heartbeat produced log entries');
cmp_ok(count_heartbeats(), '>=', 2,
    'at least 2 heartbeats observed at interval=1s');

# ALTER SYSTEM on a PGC_POSTMASTER setting cannot stop heartbeats mid-run.
$node->safe_psql('postgres',
    'ALTER SYSTEM SET sticky_honey_bun.heartbeat_interval_seconds = 0');
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');

my $before = count_heartbeats();
SHB::wait_until(sub { count_heartbeats() > $before });
cmp_ok(count_heartbeats(), '>', $before,
    'heartbeats keep firing after ALTER SYSTEM (PGC_POSTMASTER blocks runtime change)');

$node->stop;
done_testing();
