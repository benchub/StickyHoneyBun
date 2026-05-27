use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Logical-replication coverage. The README documents that subscription
# roles need USAGE on honey_bun because the apply worker invokes
# honey_bun_recv (which carries the C-level pg_type_aclcheck guard).
# This test proves the happy path end-to-end: when the subscription
# owner has USAGE, replication applies honey rows via honey_bun_recv
# and subsequent subscriber-side reads fire the trap on the subscriber's
# own log file.
#
# We don't test the negative path ("apply fails without USAGE") because
# subscription-ownership semantics changed in PG 16 (run_as_owner option,
# pg_create_subscription role) and a cross-version assertion would be
# brittle. The USAGE check itself is already proven directly by t/023.

my $pub_log = SHB::tempdir() . '/pub.log';
my $sub_log = SHB::tempdir() . '/sub.log';

my $publisher = SHB::new_node('publisher');
$publisher->init(allows_streaming => 'logical');
$publisher->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$pub_log'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$publisher->start;

my $subscriber = SHB::new_node('subscriber');
$subscriber->init;
$subscriber->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$sub_log'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$subscriber->start;

# Both clusters get the extension and a matching honey-bearing table.
for my $node ($publisher, $subscriber) {
    SHB::install_extension($node);
    $node->safe_psql('postgres', q{
        CREATE TABLE t (id int PRIMARY KEY, honey honey_bun);
    });
}

$publisher->safe_psql('postgres', 'CREATE PUBLICATION p FOR TABLE t');

# connstr returns single-quoted values for some fields (notably dbname),
# so embedding it into `CONNECTION '...'` requires doubling any inner
# single quotes per SQL string-literal escaping.
my $connstr = $publisher->connstr('postgres');
my $connstr_sql = $connstr;
$connstr_sql =~ s/'/''/g;

$subscriber->safe_psql('postgres',
    "CREATE SUBSCRIPTION s CONNECTION '$connstr_sql' PUBLICATION p");

# Stream an INSERT and wait for the subscriber to catch up.
$publisher->safe_psql('postgres',
    "INSERT INTO t VALUES (1, 'public.t.honey')");
$publisher->wait_for_catchup('s');

my $count = $subscriber->safe_psql('postgres', 'SELECT count(*) FROM t');
is($count, '1',
    'subscriber applied the honey row via honey_bun_recv');

# Read on the subscriber must fire the trap on the subscriber's log
# (not the publisher's).
my $pub_size_before = -e $pub_log ? -s $pub_log : 0;
my $sub_size_before = -e $sub_log ? -s $sub_log : 0;
$subscriber->safe_psql('postgres', 'SELECT * FROM t');

cmp_ok(-e $sub_log ? -s $sub_log : 0, '>', $sub_size_before,
    'subscriber-side read fires the trap on the subscriber log');
is(-e $pub_log ? -s $pub_log : 0, $pub_size_before,
    'subscriber-side read does not write to the publisher log');

# Cleanup: drop the subscription before stopping so the publisher's slot
# is released cleanly.
$subscriber->safe_psql('postgres', 'DROP SUBSCRIPTION s');
$subscriber->stop;
$publisher->stop;
done_testing();
