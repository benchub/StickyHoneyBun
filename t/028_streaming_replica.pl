use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Streaming-replication / hot-standby coverage. The README's End goals
# claim "Replica-safe: side effects don't touch DB state, so traps can
# still fire on hot standbys (where attackers often go)." This proves it
# end-to-end with a primary + streaming standby in the same docker
# container (PostgreSQL::Test::Cluster handles port allocation).
#
# Properties verified:
#   1. A read on the standby fires honey_bun_out via typeoutput dispatch.
#   2. The alert lands in the STANDBY's own log file — each cluster has
#      its own sticky_honey_bun.log_path.
#   3. The primary's log is NOT modified by standby-side reads.
#   4. The standby is actually a read-only replica (sanity check that we
#      didn't accidentally connect to the primary).

my $primary_log = SHB::tempdir() . '/primary.log';
my $standby_log = SHB::tempdir() . '/standby.log';

my $primary = SHB::new_node('primary');
$primary->init(allows_streaming => 1);
$primary->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$primary_log'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$primary->start;

$primary->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey');
});

# Take a base backup and stand up a streaming standby. The standby
# inherits postgresql.conf from the backup (including shared_preload_libraries
# and the primary's log_path); we override log_path so the standby writes
# alerts to its own file.
my $backup = 'standby_backup';
$primary->backup($backup);

my $standby = SHB::new_node('standby');
$standby->init_from_backup($primary, $backup, has_streaming => 1);
$standby->append_conf('postgresql.conf', qq{
sticky_honey_bun.log_path = '$standby_log'
});
$standby->start;

# Wait for the standby to replay the INSERT.
$primary->wait_for_catchup($standby);

my $primary_size_before = -e $primary_log ? -s $primary_log : 0;
ok(! -e $standby_log || -z $standby_log,
   'standby log is empty before any standby-side read');

# Read on the standby. Must fire the trap, must write to the STANDBY's
# log file, must NOT touch the primary's log.
$standby->safe_psql('postgres', 'SELECT * FROM t');

ok(-e $standby_log && -s $standby_log,
   'standby-side read produced a log entry on the standby');
is(-e $primary_log ? -s $primary_log : 0, $primary_size_before,
   'standby-side read did not write to the primary log');

# Confirm the standby's log line is well-formed and identifies the trap.
open(my $fh, '<', $standby_log) or die "cannot open $standby_log: $!";
my @lines = <$fh>;
close $fh;
is(scalar @lines, 1, 'exactly one log entry on the standby');
like($lines[0], qr/"event":"read_text"/,
     'standby log entry is read_text');
like($lines[0], qr/"tag":"public\.t\.honey"/,
     'standby log entry has the planted tag');

# Sanity: writes on the standby are refused (proves we're truly on a
# hot standby, not accidentally talking to the primary).
my ($rc, undef, $stderr) =
    $standby->psql('postgres', q{INSERT INTO t VALUES (2, 'nope')});
isnt($rc, 0,
    'standby refuses writes (confirms read-only recovery)');
like($stderr, qr/read-only|recovery/i,
    'standby write rejection is the recovery / read-only error');

$standby->stop;
$primary->stop;
done_testing();
