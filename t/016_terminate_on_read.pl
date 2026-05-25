use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# sticky_honey_bun.terminate_on_read = on causes a backend that reads a honey
# value to be terminated immediately after the alert is logged. This unmasks
# the trap to the attacker; in exchange the in-flight query is halted at the
# next CHECK_FOR_INTERRUPTS, limiting bulk exfiltration.
#
# Critical safety property: the terminate must NOT fire from the heartbeat
# bgworker, which calls the same shb_log_event(). If the terminate hook is
# placed inside the shared logger, every heartbeat would suicide the worker
# (and bgw_restart_time would restart it into the same suicide every 10s).
# The terminate must live in the typoutput / typsend call sites only.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('terminate_on_read');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 1
sticky_honey_bun.terminate_on_read = on
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey');
});

sub read_lines {
    open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    return @lines;
}

sub count_heartbeats {
    return scalar grep { /"event":"heartbeat"/ } read_lines();
}

# Let the bgworker fire some heartbeats. With heartbeat_interval=1s, 3 seconds
# yields >=2 beats only if the worker is healthy. If the terminate hook were
# (incorrectly) wired into shb_log_event(), the worker would suicide on the
# first beat and we'd see 0 or 1 heartbeat lines here.
sleep 3;

my $hb_before = count_heartbeats();
cmp_ok($hb_before, '>=', 2,
    'bgworker emits heartbeats with terminate_on_read=on (heartbeat path does not suicide)');

# Trigger the trap. With terminate_on_read=on the backend should be killed
# after the log line is emitted. psql exits non-zero; stderr indicates the
# connection was lost. Note PostgreSQL::Test::Cluster::psql returns
# ($ret, $stdout, $stderr), not the reverse.
my ($trap_rc, $trap_stdout, $trap_stderr) =
    $node->psql('postgres', 'SELECT * FROM t');
isnt($trap_rc, 0,
    'honey read terminates the backend (psql exits non-zero)');
like($trap_stderr,
     qr/terminating connection|server closed the connection|connection.*lost/i,
    'psql stderr indicates connection loss');

# The log line for the trap event must be written despite the termination:
# shb_log_event() runs to completion before pg_terminate_backend() fires.
my @lines = read_lines();
ok((grep { /"event":"read_text"/ && /"tag":"public\.t\.honey"/ } @lines),
   'trap log entry written before backend termination');

# The bgworker must survive the trap event. Heartbeats continue to arrive
# in the next interval window. (If the terminate ever reached the bgworker,
# it would die and restart on bgw_restart_time=10s, producing a 10s gap.)
sleep 3;
my $hb_after = count_heartbeats();
cmp_ok($hb_after, '>', $hb_before,
    'bgworker keeps emitting heartbeats after a trap-induced termination');

# PGC_POSTMASTER: ALTER SYSTEM cannot disable the kill at runtime, matching
# the lockdown applied to enabled / log_path / heartbeat_interval_seconds.
# pg_reload_conf records the new value but PGC_POSTMASTER means it does not
# take effect until restart, so the next trap still terminates.
$node->safe_psql('postgres',
    'ALTER SYSTEM SET sticky_honey_bun.terminate_on_read = off');
$node->psql('postgres', 'SELECT pg_reload_conf()');

my ($trap2_rc) = $node->psql('postgres', 'SELECT * FROM t');
isnt($trap2_rc, 0,
    'ALTER SYSTEM + reload does not disable terminate_on_read (PGC_POSTMASTER)');

$node->stop;
done_testing();
