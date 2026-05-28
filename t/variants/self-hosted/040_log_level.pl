# Variants: self-hosted, rds
# Asserts: the alert_log_level / heartbeat_log_level GUCs copy each
#          event into PG's own logging stream at the configured level,
#          and that sticky_honey_bun.log_path = '' disables the file
#          write entirely — so an operator can run a "log-stream only"
#          deployment without the secondary file sink.
#
# Why both knobs in one file: they're two halves of one feature
# (alternative event transport), they share the same cluster boot,
# and asserting both with one node start keeps the suite fast.

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

# Cluster A: log_path explicitly empty AND both levels set.
# log_min_messages=debug5 so LOG-level heartbeats land in the server
# log; the default log_min_messages would suppress LOG but keep
# WARNING.
my $node = SHB::new_node('log_level');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = ''
sticky_honey_bun.alert_log_level = warning
sticky_honey_bun.heartbeat_log_level = log
sticky_honey_bun.heartbeat_interval_seconds = 1
log_min_messages = debug5
});
$node->start;

SHB::install_extension($node);

my $tag = 'public.t.honey_log_level';
$node->safe_psql('postgres', qq{
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, '$tag');
});

# Fire the trap. The alert should land in PG's own server log at
# WARNING, NOT in $log_path (which is intentionally empty).
$node->safe_psql('postgres', 'SELECT * FROM t');

# 1. The secondary file sink must be absent.
ok(! -e $log_path,
   "log_path='' disables the file sink (no file created at $log_path)");

# 2. PG's server log must contain the alert JSON at WARNING.
my $log_contents = sub {
    open my $fh, '<', $node->logfile or return '';
    local $/;
    my $c = <$fh>;
    close $fh;
    return $c;
};

SHB::wait_until(sub {
    my $c = $log_contents->();
    return $c =~ /WARNING.*\Q$tag\E/s;
});

my $log = $log_contents->();
like($log, qr/WARNING.*\Q$tag\E/s,
     'alert_log_level=warning emits the alert into PG server log at WARNING');
like($log, qr/"event":"read_text"/,
     "PG server log line contains the JSON event field");
like($log, qr/\Q"tag":"$tag"\E/,
     "PG server log line contains the planted tag");

# 3. Heartbeats land at LOG level (suppressed by default
# log_min_messages, visible because we set debug5 above).
SHB::wait_until(sub {
    my $c = $log_contents->();
    return $c =~ /LOG.*"event":"heartbeat"/s;
});
$log = $log_contents->();
like($log, qr/LOG.*"event":"heartbeat"/s,
     'heartbeat_log_level=log emits heartbeats into PG server log at LOG');

# 4. The trap still returns rows transparently (no error from the
#    ereport — it's a non-throwing level).
my $rows = $node->safe_psql('postgres',
    "SELECT count(*) FROM t WHERE honey IS NOT NULL");
is($rows, '1', 'trap fire does not break the SELECT result');

$node->stop;

# -------- second cluster: levels=off, log_path set --------
# Sanity: with both log_levels at the default (off), the PG server
# log does NOT carry the JSON. Same trap fire, file sink still
# functions. This guards against a regression where the ereport
# branch fires unconditionally.

my $log_path2 = SHB::tempdir() . '/shb2.log';

my $node2 = SHB::new_node('log_level_off');
$node2->init;
$node2->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path2'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node2->start;

SHB::install_extension($node2);

my $tag2 = 'public.t.default_levels';
$node2->safe_psql('postgres', qq{
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, '$tag2');
    SELECT * FROM t;
});

ok(-e $log_path2 && -s $log_path2,
   'default levels: file sink still receives the alert');

open my $fh, '<', $node2->logfile or die "cannot read PG log: $!";
my $serverlog = do { local $/; <$fh> };
close $fh;
# Look for the JSON shape, not just the tag substring: PG's
# log_statement=all (the test-cluster default) echoes the SQL text
# itself, and the SQL literal contains the tag, so a bare /\Q$tag2\E/
# match would be a false positive. Anchoring on `"event":"read_text"`
# (which only the alert JSON ever produces) catches a real regression
# without colliding with log_statement output.
unlike($serverlog, qr/"event":"read_text".*\Q$tag2\E/,
       'default levels: PG server log does NOT contain the alert JSON '
     . '(off is off — log_statement statement echoes do not count)');

$node2->stop;
done_testing();
