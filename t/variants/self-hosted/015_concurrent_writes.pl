# Variants: self-hosted, rds
# (RDS twin is t/variants/rds/015_concurrent_writes.pl. The
# RDS variant tests that Lambda + CloudWatch queue cleanly under
# concurrent reads; this self-hosted variant tests that flock()
# prevents log-line interleaving when many backends write at once.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;
use POSIX qw(_exit);

# Probabilistic concurrency check: fire many backends doing long-query
# honey reads at the same time. With flock() in place, every JSON line
# should be intact and we should see exactly N trips logged. Without the
# lock, lines >PIPE_BUF can interleave and corrupt.
#
# This cannot deterministically reveal a race, but a regression that
# removed the lock would almost certainly fail one of the assertions
# across 100 long-line writes.

my $N_PROCS         = 10;
my $TRIPS_PER_PROC  = 10;
my $EXPECTED        = $N_PROCS * $TRIPS_PER_PROC;  # 100

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('concurrent_writes');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

# 50 distinct trap tags. Each child cycles through them; the total
# count should equal $EXPECTED regardless of which tag each trip used.
$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t
      SELECT g, 'public.t.tag_' || g
        FROM generate_series(1, 50) g;
});

my $host    = $node->host;
my $port    = $node->port;
my $padding = '/* ' . ('x' x 10000) . ' */';

my $err_dir = SHB::tempdir();

my @pids;
for my $i (0 .. $N_PROCS - 1) {
    my $pid = fork();
    die "fork failed: $!" unless defined $pid;
    if ($pid == 0) {
        # child
        my $failures = 0;
        my $errfile  = "$err_dir/child_$i.err";
        for my $j (1 .. $TRIPS_PER_PROC) {
            my $row_id = (($i * $TRIPS_PER_PROC) + $j - 1) % 50 + 1;
            my $sql = "SELECT * FROM t WHERE id = $row_id $padding";
            open(my $oldstderr, '>&', \*STDERR) or die "dup: $!";
            open(STDERR, '>>', $errfile) or die "redirect: $!";
            my $rc = system('psql',
                            '-h', $host, '-p', $port,
                            '-d', 'postgres',
                            '-X', '-A', '-t', '-q',
                            '-c', $sql);
            open(STDERR, '>&', $oldstderr) or die "restore: $!";
            $failures++ if $rc != 0;
        }
        # _exit skips Perl END blocks so the inherited PostgreSQL::Test
        # cleanup doesn't tear down the cluster out from under our siblings.
        _exit($failures);
    }
    push @pids, $pid;
}

my $child_failures = 0;
for my $pid (@pids) {
    waitpid($pid, 0);
    $child_failures += ($? >> 8);
}
if ($child_failures > 0) {
    for my $f (glob("$err_dir/child_*.err")) {
        my $err = do { open(my $fh, '<', $f); local $/; <$fh> };
        diag("$f:\n$err") if $err;
    }
}
is($child_failures, 0,
   "all $EXPECTED concurrent psql invocations succeeded");

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, $EXPECTED,
   "exactly $EXPECTED log lines (no lost or duplicated trips)");

my $parse_failures = 0;
my $tag_count      = 0;
my %tag_counts;
for my $line (@lines) {
    chomp $line;
    my $event = eval { decode_json($line) };
    if ($@) {
        $parse_failures++;
        diag("malformed line (first 200 bytes): " . substr($line, 0, 200));
        next;
    }
    if (defined $event->{tag} && $event->{tag} =~ /^public\.t\.tag_\d+$/) {
        $tag_count++;
        $tag_counts{$event->{tag}}++;
    }
}

is($parse_failures, 0,
   "every concurrent long-query line is valid JSON (no interleaving)");
is($tag_count, $EXPECTED,
   "every line carries a recognizable honey tag");

$node->stop;
done_testing();
