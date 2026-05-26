#!/usr/bin/perl
# Variants: rds
# Asserts: tools/heartbeat_poker.sh against an RDS cluster produces
#          Lambda alerts at the configured interval. Parallel concern
#          to the self-hosted bgworker heartbeat (t/009 / t/032 /
#          t/033) — the RDS variant has no bgworker, so an external
#          poker against a designated `shb_heartbeat` row is the
#          deadman source.
#
# Test strategy: plant a heartbeat row, run the poker as a child
# process for a short window with a tight interval, kill the poker,
# then verify Lambda received at least one heartbeat-tagged alert.
# We use a uniquely-tagged heartbeat row so we can probe just this
# test's alerts (other tests' run-id alerts don't pollute the count).

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use POSIX qw(:sys_wait_h);

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t803');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

my $heartbeat_tag = SHB_RDS::unique_tag($st, 'heartbeat');
$run->('CREATE TABLE shb_heartbeat (id int PRIMARY KEY, honey honey_bun)');
$run->("INSERT INTO shb_heartbeat VALUES (1, '$heartbeat_tag')");

# Fork the poker. Use libpq env vars so the poker connects to the
# right RDS endpoint and database, and PGOPTIONS to put it on the
# shb_t803 search_path (so its default query — `SELECT honey FROM
# shb_heartbeat WHERE id = 1` — resolves to our table).
my $pid = fork();
defined $pid or die "fork failed: $!";

if ($pid == 0) {
    # Child: exec the poker.
    $ENV{PGHOST}     = $st->{endpoint}{host};
    $ENV{PGPORT}     = $st->{endpoint}{port};
    $ENV{PGUSER}     = $st->{master_user};
    $ENV{PGPASSWORD} = $st->{master_password};
    $ENV{PGDATABASE} = 'postgres';
    $ENV{PGSSLMODE}  = 'require';
    $ENV{PGOPTIONS}  = '-c search_path=shb_t803,public';
    $ENV{SHB_POKER_INTERVAL} = '2';
    # Silence the poker's own progress logging; we don't need it
    # cluttering the test output.
    open STDERR, '>', '/dev/null' or die;
    exec('bash', 'tools/heartbeat_poker.sh') or die "exec failed: $!";
}

# Parent: give the poker time to fire at least one read, then kill it.
sleep 6;
kill 'TERM', $pid;
waitpid($pid, 0);
my $rc = $? >> 8;
# The poker exits 0 on SIGTERM (it traps and shuts down gracefully).
# A non-zero exit here would indicate the poker died another way.
is($rc, 0, 'poker exited cleanly on SIGTERM');

# Lambda received the heartbeat-tagged alert.
my $event = $get_event->($heartbeat_tag);
ok($event, 'Lambda received at least one heartbeat alert from poker');
is($event->{tag}, $heartbeat_tag,
    'heartbeat alert carries the planted heartbeat tag')
    if $event;

# Note on event type: the poker fires the trap via a normal SELECT,
# which dispatches through typeoutput. The alert's event field is
# therefore `read_text`, NOT `heartbeat`. The deadman-source concept
# is the steady stream of these reads — absence is the alarm, not
# the event-type label.
is($event->{event}, 'read_text',
    'poker-driven alert is read_text (typeoutput dispatch, not bgworker)')
    if $event;

done_testing();
