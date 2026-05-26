# Variants: self-hosted
# (Docker-only: the failure mode lives in PG's type system, identical
# on either variant. The RDS variant would behave the same way and
# testing it there requires a second RDS instance.)
#
# Asserts: a subscriber that does NOT have the sticky_honey_bun
#          extension cannot host a column of type `honey_bun` — DDL
#          rejection is the operator-facing failure mode. There is
#          ALSO an important operational hazard: an operator who
#          stubs the column as `text` instead can keep replication
#          flowing, but the replicated rows on the subscriber are
#          inert text — reads of them do not fire the trap because
#          honey_bun_out is never invoked. Operators who care about
#          subscriber-side trap coverage MUST install the extension
#          on every cluster that hosts honey-bearing tables.

use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $pub_log = SHB::tempdir() . '/pub.log';

my $publisher = SHB::new_node('publisher_with_ext');
$publisher->init(allows_streaming => 'logical');
$publisher->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$pub_log'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$publisher->start;

# Subscriber deliberately does NOT load sticky_honey_bun.
my $subscriber = SHB::new_node('subscriber_no_ext');
$subscriber->init;
$subscriber->start;

# Publisher has the extension + honey column.
$publisher->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int PRIMARY KEY, honey honey_bun);
});

# Failure mode 1: the operator who naively `CREATE TABLE ... honey
# honey_bun` on a subscriber without the extension is rejected at
# DDL time. This is the visible path; most operators will hit this
# first and immediately know they need the extension.
{
    my ($rc, undef, $stderr) = $subscriber->psql('postgres',
        'CREATE TABLE t (id int PRIMARY KEY, honey honey_bun)');
    isnt($rc, 0,
        'subscriber without extension cannot declare a honey_bun column');
    like($stderr, qr/type "honey_bun" does not exist/i,
        'subscriber DDL failure cites the missing type explicitly');
}

# Failure mode 2 (the silent hazard): an operator who is determined
# to keep replication flowing can stub the column as `text`. PG's
# text-format logical replication is type-loose enough to accept this
# (the wire representation is the typoutput-rendered string on the
# publisher; the subscriber stores it verbatim as text). Rows
# replicate successfully — but reads on the subscriber do NOT fire
# the trap, because the subscriber's column is plain text, not
# honey_bun, and there's no typeoutput dispatch through honey_bun_out.
$subscriber->safe_psql('postgres',
    'CREATE TABLE t (id int PRIMARY KEY, honey text)');
$publisher->safe_psql('postgres', 'CREATE PUBLICATION p FOR TABLE t');

my $connstr = $publisher->connstr('postgres');
my $connstr_sql = $connstr;
$connstr_sql =~ s/'/''/g;
$subscriber->safe_psql('postgres',
    "CREATE SUBSCRIPTION s CONNECTION '$connstr_sql' PUBLICATION p");

$publisher->safe_psql('postgres',
    "INSERT INTO t VALUES (1, 'public.t.honey')");
$publisher->wait_for_catchup('s');

my $count = $subscriber->safe_psql('postgres', 'SELECT count(*) FROM t');
is($count, '1',
    'with column stubbed as text, the row DOES replicate '
  . '(PG text-format apply does not require type identity)');

my $value = $subscriber->safe_psql('postgres',
    "SELECT honey FROM t WHERE id = 1");
is($value, 'public.t.honey',
    'replicated value is the publisher-side text representation');

# Read on the subscriber must NOT fire any trap. The publisher's
# typeoutput fired during WAL decoding on the publisher (that's the
# legitimate replication path — suppressed at the alert processor
# via the walsender's role). What we care about here is that the
# SUBSCRIBER-side read is silent — no log file on the subscriber
# (no extension, no logger), and no path through honey_bun_out.
{
    # Capture the publisher's log size before the subscriber read,
    # so we can confirm the subscriber-side read doesn't accidentally
    # cause a publisher-side firing.
    my $pub_size_before = -e $pub_log ? -s $pub_log : 0;
    $subscriber->safe_psql('postgres', 'SELECT * FROM t');
    my $pub_size_after  = -e $pub_log ? -s $pub_log : 0;
    is($pub_size_after, $pub_size_before,
        'subscriber-side read of replicated row does not fire the '
      . 'publisher trap (correct — different cluster)');
    # The subscriber has no log file because no extension. Nothing
    # to assert on the subscriber side; absence of the type alone
    # makes the trap impossible there.
}

$subscriber->safe_psql('postgres', 'DROP SUBSCRIPTION s');
$subscriber->stop;
$publisher->stop;
done_testing();
