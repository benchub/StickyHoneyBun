use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# sticky_honey_bun.heartbeat_interval_seconds is PGC_POSTMASTER: it can only
# be set in postgresql.conf at server start, so a compromised superuser
# cannot silence the heartbeat (and thereby trigger the alerter's deadman)
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

sleep 3;

ok(-e $log_path && -s $log_path, 'heartbeat produced log entries');

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

my @heartbeats = grep { /"event":"heartbeat"/ } @lines;
cmp_ok(scalar @heartbeats, '>=', 2,
    'at least 2 heartbeats in 3 seconds at interval=1s');

# ALTER SYSTEM on a PGC_POSTMASTER setting cannot stop heartbeats mid-run.
$node->safe_psql('postgres',
    'ALTER SYSTEM SET sticky_honey_bun.heartbeat_interval_seconds = 0');
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');

my $before = scalar @heartbeats;
sleep 2;

open(my $fh2, '<', $log_path) or die "cannot reopen $log_path: $!";
my @later_lines = <$fh2>;
close $fh2;
my @later_heartbeats = grep { /"event":"heartbeat"/ } @later_lines;
cmp_ok(scalar @later_heartbeats, '>', $before,
    'heartbeats keep firing after ALTER SYSTEM (PGC_POSTMASTER blocks runtime change)');

$node->stop;
done_testing();
