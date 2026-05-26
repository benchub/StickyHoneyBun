#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: many concurrent honey reads all produce alerts without loss.
#          Self-hosted t/015 tests log-file write atomicity under
#          concurrent flock; the equivalent on RDS is that Lambda Event-
#          mode invocations queue cleanly and every read produces a
#          distinct CloudWatch event.
#
# N is deliberately modest — well below Lambda's default per-region
# concurrency (1000) and CloudWatch's ingest throttles — so a green
# pass means the steady-state happy path works, not that we've
# stress-tested all the way to the limit.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use POSIX qw(_exit);

my $N = 20;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t015');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

# Plant N rows, each with a unique tag.
$run->('CREATE TABLE t (id int, honey honey_bun)');
my $batch_marker = SHB_RDS::unique_tag($st, 'concurrent_batch');
my @tags;
for my $i (1..$N) {
    my $tag = "${batch_marker}_$i";
    push @tags, $tag;
    $run->("INSERT INTO t VALUES ($i, '$tag')");
}

# Fork N parallel psql workers. Each one SELECTs a single row by id.
# We use _exit() in the child to skip Perl END blocks so the test
# harness's cleanup doesn't run prematurely.
my @pids;
for my $i (1..$N) {
    my $pid = fork();
    die "fork failed: $!" unless defined $pid;
    if ($pid == 0) {
        my ($rc) = SHB_RDS::psql_run($cs, "SELECT * FROM t WHERE id = $i");
        _exit($rc == 0 ? 0 : 1);
    }
    push @pids, $pid;
}

my $failures = 0;
for my $pid (@pids) {
    waitpid($pid, 0);
    $failures++ if ($? >> 8) != 0;
}
is($failures, 0, "all $N concurrent SELECTs succeeded");

# Each tag should produce exactly one CloudWatch event. Poll for each.
# The first poll has the highest cold-Lambda latency; subsequent polls
# are fast.
my $missed = 0;
for my $tag (@tags) {
    my $event = $get_event->($tag);
    $missed++ unless $event;
}
is($missed, 0,
    "all $N concurrent reads produced their own alert "
  . "(no events dropped under concurrency)");

# Sanity: also count alerts under the batch marker. Should be exactly N.
# This catches a regression where alerts arrive but get duplicated or
# carry the wrong tag.
sleep 5;
my $count = SHB_RDS::count_alerts($st, $batch_marker, since => 600);
is($count, $N,
    "CloudWatch contains exactly $N alerts under the batch marker");

done_testing();
