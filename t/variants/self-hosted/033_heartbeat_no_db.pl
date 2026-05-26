use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# The heartbeat bgworker historically connected to the `postgres` database,
# which made it brittle — dropping that database broke the deadman entirely.
# After the refactor the worker holds no database connection at all
# (registered with BGWORKER_SHMEM_ACCESS only, no
# BGWORKER_BACKEND_DATABASE_CONNECTION). Verify by dropping `postgres` and
# confirming heartbeats keep flowing.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('heartbeat_no_db');
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

# Baseline: heartbeats fire before any database operation.
SHB::wait_until(sub { count_heartbeats() >= 1 }, 10);
my $beats_before = count_heartbeats();
cmp_ok($beats_before, '>=', 1,
    'baseline: heartbeats fire before the postgres database is dropped');

# Drop `postgres` from template1, since you can't drop the database
# you're connected to.
$node->safe_psql('template1', 'DROP DATABASE postgres');

# After the drop, heartbeats must continue uninterrupted. With
# interval=1s we expect new beats within seconds.
SHB::wait_until(sub { count_heartbeats() > $beats_before }, 15);
cmp_ok(count_heartbeats(), '>', $beats_before,
    'heartbeats continue after postgres database is dropped');

# Sanity: a heartbeat line still parses as JSON and has the expected
# minimal shape (ts/event/tag/pid).
use JSON::PP;
open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;
my @heartbeats = grep { /"event":"heartbeat"/ } @lines;
my $obj = JSON::PP->new->decode($heartbeats[-1]);
ok($obj->{ts},                'heartbeat line carries ts');
is($obj->{event}, 'heartbeat', 'heartbeat line event is heartbeat');
is($obj->{tag},   'heartbeat', 'heartbeat line tag is heartbeat');
ok($obj->{pid} =~ /^\d+$/,    'heartbeat line carries pid');

$node->stop;
done_testing();
