use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Bgworker visibility regression guard. The heartbeat bgworker is what the
# alert processor's deadman watches for; if it ever fails to register or
# becomes invisible, silence-detection breaks. This test pins down that:
#   1. The worker is reachable via pg_stat_activity with the expected
#      backend_type and database.
#   2. Heartbeats reach the log at the configured interval.
#
# We do NOT exercise pg_terminate_backend → restart. The postmaster's
# bgw_restart_time-based restart cycle is a documented PG feature; trying
# to script it via SQL across PG 14-18 is brittle because pg_terminate_backend
# on a bgworker may deregister it rather than triggering a restart,
# depending on signal-delivery timing and PG version.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('bgworker_resilience');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 1
});
$node->start;

sub bgworker_row {
    return $node->safe_psql('postgres', q{
        SELECT pid || '|' || backend_type || '|' || datname
          FROM pg_stat_activity
         WHERE backend_type = 'sticky_honey_bun heartbeat'
    });
}

sub count_heartbeats {
    return 0 unless -e $log_path;
    open(my $fh, '<', $log_path) or return 0;
    my @lines = <$fh>;
    close $fh;
    return scalar grep { /"event":"heartbeat"/ } @lines;
}

# Worker becomes visible shortly after startup.
SHB::wait_until(sub {
    my $row = bgworker_row();
    return defined $row && $row ne '';
}, 10);

my $row = bgworker_row();
ok($row, "bgworker visible in pg_stat_activity: $row");
like($row, qr/^\d+\|sticky_honey_bun heartbeat\|postgres$/,
   'backend_type and database match the registered values');

# Heartbeats are flowing.
SHB::wait_until(sub { count_heartbeats() >= 2 }, 10);
cmp_ok(count_heartbeats(), '>=', 2,
    'bgworker is emitting heartbeats at interval=1s');

$node->stop;
done_testing();
